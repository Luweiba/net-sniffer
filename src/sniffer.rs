use pnet::datalink::{self, NetworkInterface};

use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use pnet::datalink::Channel::Ethernet;



use std::net::IpAddr;
use std::error::Error;
use std::sync::Arc;
use std::sync::Mutex;


pub struct IFace {
    name: String,
    index: u32,
}
impl IFace {
    pub fn new(name: String, index: u32) -> Self {
        Self {
            name,
            index,
        }
    }
    pub fn get_name(&self) -> String {
        self.name.clone()
    }
    pub fn get_index(&self) -> u32 {
        self.index
    }

    pub fn change_name(&mut self, name: String) {
        self.name = name;
    }
}

struct PacketInfo {
    iface_name: String,
    timestamp: u32,
    source: String,
    destination: String,
    protocol: String,
    length: u32,
    description: String,
    raw_bytes: Vec<u8>
}

impl PacketInfo {
    fn new(iface_name: String, timestamp: u32, source: String, destination: String, protocol: String, length: u32, description: String, raw_bytes: Vec<u8>) -> Self {
        Self {
            iface_name,
            timestamp,
            source,
            description,
            destination,
            raw_bytes,
            protocol,
            length
        }
    }
}

pub struct Sniffer {
    interfaces: Vec<NetworkInterface>,
    packet_info_buffer: Arc<Mutex<Vec<PacketInfo>>>
}

impl Sniffer {
    pub fn new() -> Self {
        Self {
            interfaces: datalink::interfaces(),
            packet_info_buffer: Arc::new(Mutex::new(vec![]))
        }
    }

    pub fn get_interfaces(&self) -> Vec<IFace> {
        self.interfaces.iter().map(|x| IFace::new(x.name.clone(), x.index)).collect()
    }

    pub fn start_sniffing(&self, index: u32) -> Result<(), Box<dyn Error>> {
        let interface = self.interfaces.iter().find(|x| x.index == index).unwrap();
        // Create a channel to receive on
        let (_, mut rx) = match datalink::channel(interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("packetdump: unhandled channel type: {}"),
            Err(e) => panic!("packetdump: unable to create channel: {}", e),
        };

        loop {
            let mut buf: [u8; 1600] = [0u8; 1600];
            let mut fake_ethernet_frame = MutableEthernetPacket::new(&mut buf[..]).unwrap();
            match rx.next() {
                Ok(packet) => {
                    let payload_offset;
                    if cfg!(any(target_os = "macos", target_os = "ios"))
                        && interface.is_up()
                        && !interface.is_broadcast()
                        && ((!interface.is_loopback() && interface.is_point_to_point())
                        || interface.is_loopback())
                    {
                        if interface.is_loopback() {
                            // The pnet code for BPF loopback adds a zero d out Ethernet header
                            payload_offset = 14;
                        } else {
                            // Maybe is TUN interface
                            payload_offset = 0;
                        }
                        if packet.len() > payload_offset {
                            let version = Ipv4Packet::new(&packet[payload_offset..])
                                .unwrap()
                                .get_version();
                            if version == 4 {
                                fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                                fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                                fake_ethernet_frame.set_ethertype(EtherTypes::Ipv4);
                                fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                                handle_ethernet_frame(interface, &fake_ethernet_frame.to_immutable(), self.packet_info_buffer.clone());
                                continue;
                            } else if version == 6 {
                                fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                                fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                                fake_ethernet_frame.set_ethertype(EtherTypes::Ipv6);
                                fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                                handle_ethernet_frame(interface, &fake_ethernet_frame.to_immutable(), self.packet_info_buffer.clone());
                                continue;
                            }
                        }
                    }
                    handle_ethernet_frame(interface, &EthernetPacket::new(packet).unwrap(), self.packet_info_buffer.clone());
                }
                Err(e) => panic!("packetdump: unable to receive packet: {}", e),
            }
        }
    }
}


fn handle_udp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8], buffer: Arc<Mutex<Vec<PacketInfo>>>) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        let packet_info = PacketInfo::new(interface_name.to_string(), 0, source.to_string(), destination.to_string(), "UDP".to_string(), packet.len() as u32, format!("UDP Packet: {}:{} > {}:{}; length: {}",
                                                                                                                                                                      source,
                                                                                                                                                                      udp.get_source(),
                                                                                                                                                                      destination,
                                                                                                                                                                      udp.get_destination(),
                                                                                                                                                                      udp.get_length()), packet.to_vec());
        let mut buffer_lock = buffer.lock().unwrap();
        buffer_lock.push(packet_info);
        println!(
            "[{}]: UDP Packet: {}:{} > {}:{}; length: {}",
            interface_name,
            source,
            udp.get_source(),
            destination,
            udp.get_destination(),
            udp.get_length()
        );
    } else {
        let packet_info = PacketInfo::new(interface_name.to_string(), 0, source.to_string(), destination.to_string(), "UDP".to_ascii_lowercase(), packet.len() as u32, "Malformed UDP Packet".to_string(), packet.to_vec());
        let mut buffer_lock = buffer.lock().unwrap();
        buffer_lock.push(packet_info);
        println!("[{}]: Malformed UDP Packet", interface_name);
    }
}

fn handle_icmp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8], buffer: Arc<Mutex<Vec<PacketInfo>>>) {
    let icmp_packet = IcmpPacket::new(packet);
    if let Some(icmp_packet) = icmp_packet {
        match icmp_packet.get_icmp_type() {
            IcmpTypes::EchoReply => {
                let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                let packet_info = PacketInfo::new(interface_name.to_string(), 0, source.to_string(), destination.to_string(), "ICMP".to_string(), packet.len() as u32, format!("ICMP echo reply {} -> {} (seq={:?}, id={:?})",
                                                                                                                                                                               source,
                                                                                                                                                                               destination,
                                                                                                                                                                               echo_reply_packet.get_sequence_number(),
                                                                                                                                                                               echo_reply_packet.get_identifier()), packet.to_vec());
                let mut buffer_lock = buffer.lock().unwrap();
                buffer_lock.push(packet_info);
                println!(
                    "[{}]: ICMP echo reply {} -> {} (seq={:?}, id={:?})",
                    interface_name,
                    source,
                    destination,
                    echo_reply_packet.get_sequence_number(),
                    echo_reply_packet.get_identifier()
                );
            }
            IcmpTypes::EchoRequest => {
                let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
                let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                let packet_info = PacketInfo::new(interface_name.to_string(), 0, source.to_string(), destination.to_string(), "ICMP".to_string(), packet.len() as u32, format!("[{}]: ICMP echo request {} -> {} (seq={:?}, id={:?})",
                                                                                                                                                                               interface_name,
                                                                                                                                                                               source,
                                                                                                                                                                               destination,
                                                                                                                                                                               echo_reply_packet.get_sequence_number(),
                                                                                                                                                                               echo_reply_packet.get_identifier()), packet.to_vec());
                let mut buffer_lock = buffer.lock().unwrap();
                buffer_lock.push(packet_info);
                println!(
                    "[{}]: ICMP echo request {} -> {} (seq={:?}, id={:?})",
                    interface_name,
                    source,
                    destination,
                    echo_request_packet.get_sequence_number(),
                    echo_request_packet.get_identifier()
                );
            }
            _ => {
                //let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                let packet_info = PacketInfo::new(interface_name.to_string(), 0, source.to_string(), destination.to_string(), "ICMP".to_string(), packet.len() as u32, format!("[{}]: ICMP packet {} -> {} (type={:?})",
                                                                                                                                                                               interface_name,
                                                                                                                                                                               source,
                                                                                                                                                                               destination,
                                                                                                                                                                               icmp_packet.get_icmp_type()), packet.to_vec());
                let mut buffer_lock = buffer.lock().unwrap();
                buffer_lock.push(packet_info);
                println!(
                    "[{}]: ICMP packet {} -> {} (type={:?})",
                    interface_name,
                    source,
                    destination,
                    icmp_packet.get_icmp_type()
                )
            },
        }
    } else {
        println!("[{}]: Malformed ICMP Packet", interface_name);
    }
}

fn handle_icmpv6_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8], buffer: Arc<Mutex<Vec<PacketInfo>>>) {
    let icmpv6_packet = Icmpv6Packet::new(packet);
    if let Some(icmpv6_packet) = icmpv6_packet {
        let packet_info = PacketInfo::new(interface_name.to_string(), 0, source.to_string(), destination.to_string(), "ICMP".to_string(), packet.len() as u32, format!("ICMPv6 packet {} -> {} (type={:?})",
                                                                                                                                                                       source,
                                                                                                                                                                       destination,
                                                                                                                                                                       icmpv6_packet.get_icmpv6_type()), packet.to_vec());
        let mut buffer_lock = buffer.lock().unwrap();
        buffer_lock.push(packet_info);
        println!(
            "[{}]: ICMPv6 packet {} -> {} (type={:?})",
            interface_name,
            source,
            destination,
            icmpv6_packet.get_icmpv6_type()
        )
    } else {
        println!("[{}]: Malformed ICMPv6 Packet", interface_name);
    }
}

fn handle_tcp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8], buffer: Arc<Mutex<Vec<PacketInfo>>>) {
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp {
        let packet_info = PacketInfo::new(interface_name.to_string(), 0, source.to_string(), destination.to_string(), "TCP".to_string(), packet.len() as u32, format!("TCP Packet: {}:{} > {}:{}; length: {}",
                                                                                                                                                                      source,
                                                                                                                                                                      tcp.get_source(),
                                                                                                                                                                      destination,
                                                                                                                                                                      tcp.get_destination(),
                                                                                                                                                                      packet.len()), packet.to_vec());
        let mut buffer_lock = buffer.lock().unwrap();
        buffer_lock.push(packet_info);
        println!(
            "[{}]: TCP Packet: {}:{} > {}:{}; length: {}",
            interface_name,
            source,
            tcp.get_source(),
            destination,
            tcp.get_destination(),
            packet.len()
        );
    } else {
        let packet_info = PacketInfo::new(interface_name.to_string(), 0, source.to_string(), destination.to_string(), "UDP".to_ascii_lowercase(), packet.len() as u32, "Malformed TCP Packet".to_string(), packet.to_vec());
        let mut buffer_lock = buffer.lock().unwrap();
        buffer_lock.push(packet_info);
        println!("[{}]: Malformed TCP Packet", interface_name);
    }
}

fn handle_transport_protocol(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
    buffer: Arc<Mutex<Vec<PacketInfo>>>
) {
    match protocol {
        IpNextHeaderProtocols::Udp => {
            handle_udp_packet(interface_name, source, destination, packet, buffer.clone())
        }
        IpNextHeaderProtocols::Tcp => {
            handle_tcp_packet(interface_name, source, destination, packet, buffer.clone())
        }
        IpNextHeaderProtocols::Icmp => {
            handle_icmp_packet(interface_name, source, destination, packet, buffer.clone())
        }
        IpNextHeaderProtocols::Icmpv6 => {
            handle_icmpv6_packet(interface_name, source, destination, packet, buffer.clone())
        }
        _ => {
            let packet_info = PacketInfo::new(interface_name.to_string(), 0, source.to_string(), destination.to_string(), "Unknown".to_string(), packet.len() as u32, format!("Unknown Ipv4 packet: {} > {}; protocol: {:?}", source,
                                                                                                                                                                              destination,
                                                                                                                                                                              protocol), packet.to_vec());
            let mut buffer_lock = buffer.lock().unwrap();
            buffer_lock.push(packet_info);
            println!(
                "[{}]: Unknown {} packet: {} > {}; protocol: {:?} length: {}",
                interface_name,
                match source {
                    IpAddr::V4(..) => "IPv4",
                    _ => "IPv6",
                },
                source,
                destination,
                protocol,
                packet.len()
            )
        },
    }
}

fn handle_ipv4_packet(interface_name: &str, ethernet: &EthernetPacket, buffer: Arc<Mutex<Vec<PacketInfo>>>) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            interface_name,
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.payload(),
            buffer.clone()
        );
    } else {
        let packet_info = PacketInfo::new(interface_name.to_string(), 0, "#".to_string(), "#".to_string(), "Unknown".to_string(), ethernet.packet().len() as u32, "Malformed IPv4 Packet".to_string(), ethernet.packet().to_vec());
        let mut buffer_lock = buffer.lock().unwrap();
        buffer_lock.push(packet_info);
    }
}

fn handle_ipv6_packet(interface_name: &str, ethernet: &EthernetPacket, buffer: Arc<Mutex<Vec<PacketInfo>>>) {
    let header = Ipv6Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            interface_name,
            IpAddr::V6(header.get_source()),
            IpAddr::V6(header.get_destination()),
            header.get_next_header(),
            header.payload(),
            buffer.clone()
        );
    } else {
        let packet_info = PacketInfo::new(interface_name.to_string(), 0, "#".to_string(), "#".to_string(), "Unknown".to_string(), ethernet.packet().len() as u32, "Malformed IPv6 Packet".to_string(), ethernet.packet().to_vec());
        let mut buffer_lock = buffer.lock().unwrap();
        buffer_lock.push(packet_info);
    }
}

fn handle_arp_packet(interface_name: &str, ethernet: &EthernetPacket, buffer: Arc<Mutex<Vec<PacketInfo>>>) {
    let header = ArpPacket::new(ethernet.payload());
    if let Some(header) = header {
        let packet_info = PacketInfo::new(interface_name.to_string(), 0, ethernet.get_source().to_string(), ethernet.get_destination().to_string(), "ARP".to_string(), ethernet.packet().len() as u32, format!("ARP packet: {}({}) > {}({}); operation: {:?}", ethernet.get_source(),
                                                                                                                                                                                header.get_sender_proto_addr(),
                                                                                                                                                                                ethernet.get_destination(),
                                                                                                                                                                                header.get_target_proto_addr(),
                                                                                                                                                                                header.get_operation()), ethernet.packet().to_vec());
        let mut buffer_lock = buffer.lock().unwrap();
        buffer_lock.push(packet_info);
        println!(
            "[{}]: ARP packet: {}({}) > {}({}); operation: {:?}",
            interface_name,
            ethernet.get_source(),
            header.get_sender_proto_addr(),
            ethernet.get_destination(),
            header.get_target_proto_addr(),
            header.get_operation()
        );
    } else {
        let packet_info = PacketInfo::new(interface_name.to_string(), 0, "#".to_string(), "#".to_string(), "Unknown".to_string(), ethernet.packet().len() as u32, "Malformed ARP Packet".to_string(), ethernet.packet().to_vec());
        let mut buffer_lock = buffer.lock().unwrap();
        buffer_lock.push(packet_info);
    }
}

fn handle_ethernet_frame(interface: &NetworkInterface, ethernet: &EthernetPacket, buffer: Arc<Mutex<Vec<PacketInfo>>>) {
    let interface_name = &interface.name[..];
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(interface_name, ethernet, buffer.clone()),
        EtherTypes::Ipv6 => handle_ipv6_packet(interface_name, ethernet, buffer.clone()),
        EtherTypes::Arp => handle_arp_packet(interface_name, ethernet, buffer.clone()),
        _ => {
            let packet_info = PacketInfo::new(interface_name.to_string(), 0, ethernet.get_source().to_string(), ethernet.get_destination().to_string(), "Unknown".to_string(), ethernet.packet().len() as u32, format!("Unknown packet; ethertype: {:?}", ethernet.get_ethertype()), ethernet.packet().to_vec());
            let mut buffer_lock = buffer.lock().unwrap();
            buffer_lock.push(packet_info);
        }
    }
}
