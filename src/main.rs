extern crate icmp;
extern crate dns_lookup;
extern crate ipaddress;
extern crate hostname_validator;

use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::env;
use std::thread;
use std::time::{Duration, SystemTime};
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::{IcmpPacket, IcmpTypes, IcmpCode, checksum};
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::Packet;
use ipaddress::IPAddress;

fn main() {
    let mut packets_lost = 0.0;
    let mut packets_sent = 0.0;

    let args: Vec<String> = env::args().collect();
    let arg = &args[1];
    let mut ip = String::from(arg);
    let mut maybe_ipv6 = false;
    let mut maybe_hostname = false;
    let mut maybe_ipv4 = false;
    if ip.contains(":") {
        // this is maybe ipv6
        maybe_ipv6 = true;
    } else if arg.chars().any(char::is_alphabetic) {
        // might be a hostname
        maybe_hostname = true;
    } else {
        maybe_ipv4 = true;
    }
    // if maybe_hostname {
    //
    // }
    // let is_hostname = arg.chars().any(char::is_alphabetic);
    // if is_hostname {
    //     let ips: Vec<std::net::IpAddr> = lookup_host(arg).unwrap();
    //     ip = ips[0].to_string();
    //     println!("{}", ip);
    // }
    let mut temp = None;
    let mut ip_address = None;
    // let temp = IPAddress::parse(arg).unwrap();
    if maybe_hostname {
        println!("might be hostname");
        let ips: Vec<std::net::IpAddr> = dns_lookup::lookup_host(arg).unwrap();
        ip = ips[0].to_string();
        temp = Some(IPAddress::parse(ip.to_string()).unwrap());
    } else {
        temp = Some(IPAddress::parse(arg).unwrap());
        if Some(temp).is_ipv4() {
            ip_address = Some(IpAddr::V4(Ipv4Addr::from_str(&arg)));
        }
    }


    // if temp.is_ipv4() {
    //     println!("is ipv4");
    // } else if temp.is_ipv6() {
    //     println!("is ipv6");
    // } else {
    //     println!("might be hostname");
    //     let ips: Vec<std::net::IpAddr> = dns_lookup::lookup_host(arg).unwrap();
    //     ip = ips[0].to_string();
    //     temp = Some(IPAddress::parse(ip.to_string()).unwrap());
    // }
    //
    // let ip_address = match net::IpAddr::from_str(&ip) {
    //     Ok(addr) => addr,
    //     Err(error) => {
    //         panic!("Problem creating the IP address: {:?}", error)
    //     },
    // };

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
        println!("made it to here");
        let elapsed = match now.elapsed() {
            Ok(elapsed) => elapsed.as_millis(),
            Err(_error) => 0,
        };
        if let Some(_icmp_packet) = EchoReplyPacket::new(&buf[20..]) {
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
