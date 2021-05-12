use actix_web::{
    error, middleware, web, App, Error, HttpRequest, HttpResponse, HttpServer, get
};
use futures::StreamExt;
use json::JsonValue;
use serde::{Deserialize, Serialize};
use std::cell::{Cell, RefCell};
use std::sync::Arc;
use net_sniffer::sniffer::IFace;
use std::borrow::{Borrow, BorrowMut};

#[derive(Debug, Serialize, Deserialize)]
struct MyObj {
    name: String,
    number: i32,
}

/// This handler uses json extractor
async fn index(item: web::Json<MyObj>) -> HttpResponse {
    println!("model: {:?}", &item);
    HttpResponse::Ok().json(item.0) // <- send response
}

/// This handler uses json extractor with limit
async fn extract_item(item: web::Json<MyObj>, req: HttpRequest) -> HttpResponse {
    println!("request: {:?}", req);
    println!("model: {:?}", item);

    HttpResponse::Ok().json(item.0) // <- send json response
}

const MAX_SIZE: usize = 262_144; // max payload size is 256k

/// This handler manually load request payload and parse json object
async fn index_manual(mut payload: web::Payload) -> Result<HttpResponse, Error> {
    // payload is a stream of Bytes objects
    let mut body = web::BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk?;
        // limit max size of in-memory payload
        if (body.len() + chunk.len()) > MAX_SIZE {
            return Err(error::ErrorBadRequest("overflow"));
        }
        body.extend_from_slice(&chunk);
    }

    // body is loaded, now we can deserialize serde-json
    let obj = serde_json::from_slice::<MyObj>(&body)?;
    Ok(HttpResponse::Ok().json(obj)) // <- send response
}

/// This handler manually load request payload and parse json-rust
async fn index_mjsonrust(body: web::Bytes) -> Result<HttpResponse, Error> {
    // body is loaded, now we can deserialize json-rust
    let result = json::parse(std::str::from_utf8(&body).unwrap()); // return Result
    let injson: JsonValue = match result {
        Ok(v) => v,
        Err(e) => json::object! {"err" => e.to_string() },
    };
    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .body(injson.dump()))
}

#[get("/iface_get")]
async fn iface_get(mut data: web::Data<MyData>) -> Result<HttpResponse, Error> {
    data.iface.borrow_mut().change_name("eth2".to_string());
    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .body(json::object! {
            "Name": data.iface.borrow().get_name(),
            "index": data.iface.borrow().get_index()
        }.dump()))
}

struct MyData {
    iface: RefCell<IFace>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "actix_web=info");
    env_logger::init();

    HttpServer::new(|| {
        App::new()
            // enable logger
            .data(MyData{ iface: RefCell::new(IFace::new("eth0".to_string(), 1))})
            .wrap(middleware::Logger::default())
            .wrap(middleware::DefaultHeaders::new().header("Access-Control-Allow-Origin", "*"))
            .data(web::JsonConfig::default().limit(4096)) // <- limit size of the payload (global configuration)
            .service(web::resource("/extractor").route(web::post().to(index)))
            .service(
                web::resource("/extractor2")
                    .data(web::JsonConfig::default().limit(1024)) // <- limit size of the payload (resource level)
                    .route(web::post().to(extract_item)),
            )
            .service(web::resource("/manual").route(web::post().to(index_manual)))
            .service(web::resource("/mjsonrust").route(web::post().to(index_mjsonrust)))
            .service(web::resource("/").route(web::post().to(index)))
            .service(iface_get)
    })
        .bind("127.0.0.1:8080")?
        .run()
        .await
}
