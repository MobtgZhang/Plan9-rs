//! Network Statistics Command
//!
//! Implementation of the netstat command for showing network connections and statistics.

use std::env;

pub struct NetstatOptions {
    pub all: bool,
    pub numeric: bool,
    pub tcp: bool,
    pub udp: bool,
    pub unix: bool,
    pub listening: bool,
    pub verbose: bool,
    pub continuous: bool,
    pub extended: bool,
}

impl Default for NetstatOptions {
    fn default() -> Self {
        NetstatOptions {
            all: false,
            numeric: false,
            tcp: false,
            udp: false,
            unix: false,
            listening: false,
            verbose: false,
            continuous: false,
            extended: false,
        }
    }
}

impl NetstatOptions {
    pub fn parse(args: &[String]) -> Self {
        let mut opts = NetstatOptions::default();

        for arg in args {
            match arg.as_str() {
                "-a" | "--all" => opts.all = true,
                "-n" | "--numeric" => opts.numeric = true,
                "-t" | "--tcp" => opts.tcp = true,
                "-u" | "--udp" => opts.udp = true,
                "-x" | "--unix" => opts.unix = true,
                "-l" | "--listening" => opts.listening = true,
                "-v" | "--verbose" => opts.verbose = true,
                "-c" | "--continuous" => opts.continuous = true,
                "-e" | "--extended" => opts.extended = true,
                _ if arg.starts_with('-') => {}
                _ => {}
            }
        }

        // If no protocol specified, show all
        if !opts.tcp && !opts.udp && !opts.unix {
            opts.tcp = true;
            opts.udp = true;
        }

        opts
    }
}

fn show_tcp_connections(opts: &NetstatOptions) {
    println!("Active Internet connections (only servers)");

    if opts.verbose || opts.extended {
        println!("Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name");
    } else if opts.numeric {
        println!("Proto Recv-Q Send-Q Local Address           Foreign Address         State");
    } else {
        println!("Proto Recv-Q Send-Q Local Address           Foreign Address         State");
    }

    // Simulated TCP connections
    println!("tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1234/sshd");
    println!("tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      1234/cupsd");
    println!("tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1234/nginx");
    println!("tcp        0      0 192.168.1.100:22         192.168.1.50:54321       ESTABLISHED  1234/sshd");
    println!("tcp        0      0 192.168.1.100:80         192.168.1.50:54322       TIME_WAIT   -");
}

fn show_udp_connections(opts: &NetstatOptions) {
    println!("\nActive Internet connections (without servers)");

    if opts.verbose || opts.extended {
        println!("Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name");
    } else {
        println!("Proto Recv-Q Send-Q Local Address           Foreign Address         State");
    }

    // Simulated UDP connections
    println!("udp        0      0 0.0.0.0:68              0.0.0.0:*                          1234/dhcpcd");
    println!("udp        0      0 0.0.0.0:5353            0.0.0.0:*                          1234/avahi-daemon");
    println!("udp        0      0 127.0.0.1:323           0.0.0.0:*                          1234/chronyd");
}

fn show_unix_sockets(opts: &NetstatOptions) {
    println!("\nActive UNIX domain sockets (servers and established)");

    if opts.verbose || opts.extended {
        println!("Proto RefCnt Flags       Type       State         I-Node   PID/Program name    Path");
    } else {
        println!("Proto RefCnt Flags       Type       State         I-Node   Path");
    }

    // Simulated UNIX sockets
    println!("unix  2      [ ACC ]     STREAM     LISTENING     12345   1234/systemd         /run/systemd/private");
    println!("unix  2      [ ACC ]     STREAM     LISTENING     12346   1234/dbus-daemon      /run/dbus/system_bus_socket");
    println!("unix  2      [ ]         DGRAM      CONNECTED     12347   1234/systemd-logind    /run/systemd/journal/socket");
    println!("unix  1      [ ]         DGRAM      UNCONNECTED   12348   -                    /run/systemd/journal/dev-log");
}

fn show_routing_table(_opts: &NetstatOptions) {
    println!("\nKernel IP routing table");
    println!("Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface");
    println!("0.0.0.0         192.168.1.1     0.0.0.0         UG        0 0          0 eth0");
    println!("192.168.1.0     0.0.0.0         255.255.255.0   U         0 0          0 eth0");
    println!("127.0.0.0       0.0.0.0         255.0.0.0       U         0 0          0 lo");
}

fn show_interface_stats(_opts: &NetstatOptions) {
    println!("\nKernel Interface table");
    println!("Iface      MTU    RX-OK RX-ERR RX-DRP RX-OVR    TX-OK TX-ERR TX-DRP TX-OVR Flg");
    println!("lo       65536      100      0      0      0        100      0      0      0 BMRU");
    println!("eth0      1500     1000      0      0      0        500      0      0      0 BMRU");
}

pub fn run_netstat(args: &[String]) -> i32 {
    let opts = NetstatOptions::parse(args);

    // Check for routing table flag
    if args.contains(&"-r".to_string()) || args.contains(&"--route".to_string()) {
        show_routing_table(&opts);
        return 0;
    }

    // Check for interface flag
    if args.contains(&"-i".to_string()) || args.contains(&"--interfaces".to_string()) {
        show_interface_stats(&opts);
        return 0;
    }

    // Show connections
    if opts.tcp {
        show_tcp_connections(&opts);
    }

    if opts.udp {
        show_udp_connections(&opts);
    }

    if opts.unix {
        show_unix_sockets(&opts);
    }

    0
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_netstat(&args);
    std::process::exit(status);
}
