use actix_web::{
    error, middleware, web, App, Error, HttpRequest, HttpResponse, HttpServer, get
};
use futures::StreamExt;
use json::JsonValue;
use serde::{Deserialize, Serialize};
use std::cell::{Cell, RefCell};
use std::sync::Arc;
use net_sniffer::sniffer::{IFace, Sniffer};
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
#[get("/iface_select/{index}")]
async fn iface_select(index: web::Path<u32>, data: web::Data<MyData>) -> Result<HttpResponse, Error> {
    let index = index.0;
    println!("Get index {}", index);
    data.sniffer.borrow_mut().start_sniffing(index);
    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .body(json::Null.dump()))
}


#[get("/iface_get")]
async fn iface_get(mut data: web::Data<MyData>) -> Result<HttpResponse, Error> {
    let interfaces = data.sniffer.borrow().get_interfaces();
    let mut iface_json = JsonValue::new_array();
    for iface in interfaces {
         iface_json.push(json::object! {
             "name": iface.get_name(),
             "index": iface.get_index()
         });
    }
    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .body(iface_json.dump()))
}

#[get("/packet_update")]
async fn packet_update(mut data: web::Data<MyData>) -> Result<HttpResponse, Error> {
    let packets = data.sniffer.borrow_mut().packet_update();
    let mut packets_json = JsonValue::new_array();
    for packet in packets {
        let (iface_name, timestamp, source, destination, protocol, length, description, raw_bytes) = packet.get_inner();
        packets_json.push(json::object! {
            "iface_name": iface_name,
            "timestamp": timestamp,
            "source": source,
            "destination": destination,
            "protocol": protocol,
            "length": length,
            "description": description,
            "raw_bytes": raw_bytes
       });
    }
    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .body(packets_json.dump()))

}

#[get("/stop_sniffing")]
async fn stop_sniffing(mut data: web::Data<MyData>) -> Result<HttpResponse, Error> {
    let signal = data.sniffer.borrow_mut().packet_update_stop();
    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .body(JsonValue::Boolean(signal).dump()))
}

struct MyData {
    sniffer: RefCell<Sniffer>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "actix_web=info");
    env_logger::init();

    HttpServer::new(|| {
        App::new()
            // enable logger
            .data(MyData{ sniffer: RefCell::new(Sniffer::new())})
            .wrap(middleware::Logger::default())
            .wrap(middleware::DefaultHeaders::new().header("Access-Control-Allow-Origin", "*"))
            .data(web::JsonConfig::default().limit(4096)) // <- limit size of the payload (global configuration)
            .service(iface_get)
            .service(iface_select)
            .service(packet_update)
            .service(stop_sniffing)
    })
        .bind("127.0.0.1:8080")?
        .run()
        .await
}
