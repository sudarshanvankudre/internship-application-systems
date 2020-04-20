extern crate icmp;
extern crate ctrlc;

use std::net;
use std::str::FromStr;
use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime};
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::{IcmpPacket, IcmpTypes, IcmpCode, checksum};
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::Packet;

fn main() {
    let mut packets_lost = 0.0;
    let mut packets_sent = 0.0;

    let args: Vec<String> = env::args().collect();
    let ip = &args[1];
    let ip_address = match net::IpAddr::from_str(ip) {
        Ok(addr) => addr,
        Err(error) => {
            panic!("Problem creating the IP address: {:?}", error)
        },
    };

    let ping = icmp::IcmpSocket::connect(ip_address);
    let mut ping = ping.unwrap();
    let packet_size = 64; // arbitrary
    let mut sequence_number: u16 = 0;

    loop {
        let mut buf: Vec<u8> = vec![0; packet_size];
        let identifier: u16 = 0;

        make_packet(&sequence_number, &identifier, &mut buf[..]);
        let now = SystemTime::now();
        ping.send(&buf[..]);
        packets_sent += 1.0;
        ping.recv(&mut buf[..]);
        let elapsed = match now.elapsed() {
            Ok(elapsed) => elapsed.as_millis(),
            Err(_error) => 0,
        };
        if let Some(icmp_packet) = EchoReplyPacket::new(&buf[20..]) {
            println!("reply from {}: icmp_seq={} time={}ms packet_loss={}%",
            ip_address.to_string(), sequence_number, elapsed, packets_lost / packets_sent * 100.0);
        } else {
            packets_lost += 1.0;
        }
        println!("success!");
        thread::sleep(Duration::new(1, 0));
        sequence_number += 1;
    }
}

fn make_packet(&sequence_number: &u16, &identifier: &u16, buf: &mut [u8]) {
    let mut echo_packet = MutableEchoRequestPacket::new(buf).unwrap();
    echo_packet.set_sequence_number(sequence_number);
    echo_packet.set_identifier(identifier);
    echo_packet.set_icmp_type(IcmpTypes::EchoRequest);
    echo_packet.set_icmp_code(IcmpCode::new(0));
    let echo_checksum = checksum(&IcmpPacket::new(echo_packet.packet()).unwrap());
    echo_packet.set_checksum(echo_checksum);
}
