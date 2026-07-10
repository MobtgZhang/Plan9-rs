//! IP Configuration Command
//!
//! Implementation of the ip command for network configuration.

// ============================================================================
// Options
// ============================================================================

#[derive(Debug, Clone)]
pub enum IpAction {
    Show,
    Add,
    Del,
    Flush,
}

#[derive(Debug, Clone)]
pub struct IpOptions {
    pub action: IpAction,
    pub family: Option<String>,  // -family: inet, inet6
    pub show: bool,
    pub brief: bool,
}

impl Default for IpOptions {
    fn default() -> Self {
        IpOptions {
            action: IpAction::Show,
            family: None,
            show: false,
            brief: false,
        }
    }
}

// ============================================================================
// Network Interfaces (simulated)
// ============================================================================

struct NetworkInterface {
    name: String,
    state: String,
    mtu: u32,
    ip: Option<String>,
    mac: String,
}

fn get_interfaces() -> Vec<NetworkInterface> {
    vec![
        NetworkInterface {
            name: "lo".to_string(),
            state: "UP".to_string(),
            mtu: 65536,
            ip: Some("127.0.0.1/8".to_string()),
            mac: "00:00:00:00:00:00".to_string(),
        },
        NetworkInterface {
            name: "eth0".to_string(),
            state: "UP".to_string(),
            mtu: 1500,
            ip: Some("192.168.1.100/24".to_string()),
            mac: "52:54:00:12:34:56".to_string(),
        },
    ]
}

// ============================================================================
// Implementation
// ============================================================================

pub fn run_ip(args: &[String]) -> i32 {
    let mut opts = IpOptions::default();
    let mut targets = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "link" | "addr" | "route" | "neigh" => {
                targets.push(args[i].clone());
            }
            "show" | "list" | "ls" => opts.show = true,
            "add" => opts.action = IpAction::Add,
            "del" | "delete" => opts.action = IpAction::Del,
            "flush" => opts.action = IpAction::Flush,
            "-4" => opts.family = Some("inet".to_string()),
            "-6" => opts.family = Some("inet6".to_string()),
            "-br" | "-brief" => opts.brief = true,
            _ if !args[i].starts_with('-') => {
                targets.push(args[i].clone());
            }
            _ => {}
        }
        i += 1;
    }

    if targets.is_empty() || targets.contains(&"link".to_string()) {
        show_links(&opts);
    }

    if targets.contains(&"addr".to_string()) {
        show_addresses(&opts);
    }

    if targets.contains(&"route".to_string()) {
        show_routes(&opts);
    }

    if targets.contains(&"neigh".to_string()) {
        show_neighbours(&opts);
    }

    0
}

fn show_links(opts: &IpOptions) {
    for iface in get_interfaces() {
        println!(
            "{}: {}: <{}> mtu {} state {}",
            iface.name, iface.name, iface.state, iface.mtu, iface.state
        );
        println!("    link/ether {} brd ff:ff:ff:ff:ff:ff", iface.mac);
        if opts.brief {
            println!("    {}", iface.mac);
        }
    }
}

fn show_addresses(opts: &IpOptions) {
    for iface in get_interfaces() {
        if let Some(ip) = &iface.ip {
            if opts.brief {
                println!("{} {}", iface.name, ip);
            } else {
                println!("{}: {} scope global {} valid_lft forever preferred_lft forever", iface.name, ip, iface.name);
            }
        }
    }
}

fn show_routes(_opts: &IpOptions) {
    println!("default via 192.168.1.1 dev eth0 proto static");
    println!("192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100");
    println!("127.0.0.0/8 dev lo proto kernel scope host src 127.0.0.1");
}

fn show_neighbours(_opts: &IpOptions) {
    println!("192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE");
    println!("192.168.1.100 dev eth0 lladdr 52:54:00:12:34:56 PERMANENT");
}

