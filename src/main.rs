use bytes::{Buf, BufMut, BytesMut, IntoBuf};
use std::fmt;
use std::net::UdpSocket;

#[derive(Default)]
struct DNSResponse {
    id: u16,
    qr: bool,
    opcode: u8,
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    z: u8,
    rcode: u8,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

impl<'a> DNSResponse {
    fn new() -> DNSResponse {
        DNSResponse {
            id: rand::random::<u16>(),
            qr: false,
            opcode: 0,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            z: 0,
            rcode: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
            ..Default::default()
        }
    }

    fn from_buffer(&mut self, buf: &mut Buf) {
        self.id = buf.get_u16_le();

        let mut byte = buf.get_u8();
        self.qr = if byte & 0b10000000 > 0 { true } else { false };
        self.opcode = byte & 0b01111000;
        self.aa = if byte & 0b00000100 > 0 { true } else { false };
        self.tc = if byte & 0b00000010 > 0 { true } else { false };
        self.rd = if byte & 0b00000001 > 0 { true } else { false };

        byte = buf.get_u8();
        self.ra = if byte & 0b10000000 > 0 { true } else { false };
        self.z = byte & 0b01110000;
        self.rcode = byte & 0b00001111;
    }
}

#[derive(Default)]
struct DNSRequest<'a> {
    id: u16,
    qr: bool,
    opcode: u8,
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    z: u8,
    rcode: u8,
    ancount: u16,
    nscount: u16,
    arcount: u16,
    names: Vec<Vec<&'a str>>,
}

impl<'a> DNSRequest<'a> {
    fn new() -> DNSRequest<'a> {
        DNSRequest {
            id: rand::random::<u16>(),
            qr: false,
            opcode: 0,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            z: 0,
            rcode: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
            ..Default::default()
        }
    }

    fn to_buffer(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(1024);

        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // | ID                    .                       |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |QR| Opcode    |AA|TC|RD|RA| Z      | RCODE     |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // | QDCOUNT               .                       |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // | ANCOUNT               .                       |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // | NSCOUNT               .                       |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // | ARCOUNT               .                       |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        // 16 bits - id
        buf.put_u16_le(self.id);

        // 8 bits
        //  QR      - 1 bit
        //  Opcode  - 4 bits
        //  AA      - 1 bit
        //  TC      - 1 bit
        //  RD      - 1 bit
        let mut bt: u8 = self.opcode;
        bt <<= 3;
        if self.qr == true {
            bt ^= 0b10000000;
        }
        if self.aa == true {
            bt ^= 0b00000100;
        }
        if self.tc == true {
            bt ^= 0b00000010;
        }
        if self.rd == true {
            bt ^= 0b00000001;
        }
        buf.put_u8(bt);

        // 8 bits
        //  RA      - 1 bit
        //  Z       - 3 bits
        //  Rcode   - 4 bits
        bt = self.z;
        bt <<= 4;
        if self.ra == true {
            bt ^= 0b10000000;
        }
        bt ^= self.rcode & 0b00001111;
        buf.put_u8(bt);

        // 16 bits (QDCOUNT)
        buf.put_u16_be(self.qdcount());

        // 16 bits (ANCOUNT)
        buf.put_u16_be(self.ancount);

        // 16 bits (NSCOUNT)
        buf.put_u16_be(self.nscount);

        // 16 bits (ARCOUNT)
        buf.put_u16_be(self.arcount);

        // Names
        for name in &self.names {
            for part in name {
                buf.put_u8(part.len() as u8);
                for c in part.chars() {
                    buf.put_u8(c as u8);
                }
            }
            buf.put_u8(0); // End of name

            // QTYPE (Type A Query - host address)
            buf.put_u8(0);
            buf.put_u8(1);

            // QCLASS (Class IN - internet address)
            buf.put_u8(0);
            buf.put_u8(1);
        }

        buf
    }

    fn add_question(&mut self, name: &'a String) {
        // TODO: Validate name (only dots and numalpha?)

        let parts: Vec<_> = name.split('.').map(|x| x).collect();
        self.names.push(parts);
    }

    fn qdcount(&self) -> u16 {
        self.names.len() as u16
    }
}

fn get_bits(num: u16, count: usize) -> String {
    let mut mask = 1;
    let mut counter = count;
    loop {
        counter -= 1;
        if counter == 0 {
            break;
        }
        mask <<= 1;
        mask |= 1;
    }
    let opcode = num & mask;
    let binary_string = format!("{:016b}", opcode);
    binary_string.chars().skip(16 - count).collect()
}

impl fmt::Debug for DNSResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "--- Begin of packet ---");
        writeln!(f, "id:\t{}", self.id);
        writeln!(f, "qr:\t{}", self.qr);
        writeln!(f, "opcode:\t{}", get_bits(self.opcode as u16, 4));
        writeln!(f, "aa:\t{}", self.aa);
        writeln!(f, "tc:\t{}", self.tc);
        writeln!(f, "rd:\t{}", self.rd);
        writeln!(f, "ra:\t{}", self.ra);
        writeln!(f, "z:\t{}", get_bits(self.z as u16, 3));
        writeln!(f, "rcode:\t{}", get_bits(self.rcode as u16, 4));
        writeln!(f, "--");
        //writeln!(f, "qdcount:\t{}", get_bits(self.qdcount(), 16));
        writeln!(f, "ancount:\t{}", get_bits(self.ancount, 16));
        writeln!(f, "nscount:\t{}", get_bits(self.nscount, 16));
        writeln!(f, "arcount:\t{}", get_bits(self.arcount, 16));
        writeln!(f, "--");
        let mut name_count = 1;
        /*
        for n in &self.names {
            writeln!(f, "name #{}:", name_count);
            name_count += 1;
            for part in n {
                writeln!(f, "(len: {})\t{}", part.len(), part);
            }
        }
        */
        writeln!(f, "--- End of packet ---")
    }
}

impl<'a> fmt::Debug for DNSRequest<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "--- Begin of packet ---");
        writeln!(f, "id:\t{}", self.id);
        writeln!(f, "qr:\t{}", self.qr);
        writeln!(f, "opcode:\t{}", get_bits(self.opcode as u16, 4));
        writeln!(f, "aa:\t{}", self.aa);
        writeln!(f, "tc:\t{}", self.tc);
        writeln!(f, "rd:\t{}", self.rd);
        writeln!(f, "ra:\t{}", self.ra);
        writeln!(f, "z:\t{}", get_bits(self.z as u16, 3));
        writeln!(f, "rcode:\t{}", get_bits(self.rcode as u16, 4));
        writeln!(f, "--");
        writeln!(f, "qdcount:\t{}", get_bits(self.qdcount(), 16));
        writeln!(f, "ancount:\t{}", get_bits(self.ancount, 16));
        writeln!(f, "nscount:\t{}", get_bits(self.nscount, 16));
        writeln!(f, "arcount:\t{}", get_bits(self.arcount, 16));
        writeln!(f, "--");
        let mut name_count = 1;
        for n in &self.names {
            writeln!(f, "name #{}:", name_count);
            name_count += 1;
            for part in n {
                writeln!(f, "(len: {})\t{}", part.len(), part);
            }
        }
        writeln!(f, "--- End of packet ---")
    }
}

fn dump_buffer(buf: &bytes::BytesMut) {
    println!("Binary packet representation:");

    let mut space_counter = 0;
    let mut group_counter = 0;
    for i in buf.iter() {
        print!("{:02x}", i);
        space_counter += 1;
        if (space_counter % 2) == 0 {
            print!(" ");
            group_counter += 1;
            if (group_counter % 8) == 0 {
                println!();
            }
        }
    }
    println!();
}

fn main() {
    let mut req = DNSRequest::new();

    let name01 = String::from("www.wp.pl");
    let name02 = String::from("www.vatican.va");
    req.add_question(&name01);
    req.add_question(&name02);
    println!("{:?}", req);

    let binary_representation = req.to_buffer();
    dump_buffer(&binary_representation);

    let socket = UdpSocket::bind("0.0.0.0:0").expect("Couldn't bind to address");
    socket
        .send_to(&binary_representation[..], ("8.8.8.8", 53))
        .expect("Couldn't send DNS request");

    let mut buf = [0; 2048];
    let (amt, _) = socket
        .recv_from(&mut buf)
        .expect("Couldn't receive response");

    println!();
    println!("Received {} bytes of response\n", amt);

    let mut bb = BytesMut::with_capacity(amt);
    for x in 0..amt {
        bb.put_u8(buf[x]);
    }
    dump_buffer(&bb);

    let mut xxx = buf.into_buf();
    let mut resp = DNSResponse::new();
    resp.from_buffer(&mut xxx);

    println!();
    println!("{:?}", resp);
}
