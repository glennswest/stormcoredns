//! `bind` — the addresses (or interfaces) the server listens on.
//!
//! ```text
//! bind ADDRESS|INTERFACE ... {
//!     except ADDRESS ...
//! }
//! ```

use crate::plugin::Controller;
use std::collections::HashSet;
use std::net::IpAddr;

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut all: Vec<String> = Vec::new();
    let mut except: HashSet<IpAddr> = HashSet::new();
    let ifaces = interfaces();
    while c.next() {
        let args = c.remaining_args_until_brace();
        if args.is_empty() {
            return Err(c.errf("at least one address or interface name is expected"));
        }
        let mut wants = Vec::new();
        for a in &args {
            if let Ok(ip) = a.parse::<IpAddr>() {
                wants.push(ip);
                continue;
            }
            match ifaces.iter().filter(|(n, _)| n == a).map(|(_, ip)| *ip).collect::<Vec<_>>() {
                v if !v.is_empty() => wants.extend(v),
                _ => return Err(c.errf(format!("not a valid IP address or interface name: \"{}\"", a))),
            }
        }
        while c.next_block() {
            match c.val() {
                "except" => {
                    for e in c.remaining_args() {
                        match e.parse::<IpAddr>() {
                            Ok(ip) => {
                                except.insert(ip);
                            }
                            Err(_) => {
                                let v: Vec<IpAddr> = ifaces.iter().filter(|(n, _)| *n == e).map(|(_, ip)| *ip).collect();
                                if v.is_empty() {
                                    return Err(c.errf(format!("not a valid IP address or interface name: \"{}\"", e)));
                                }
                                except.extend(v);
                            }
                        }
                    }
                }
                other => return Err(c.errf(format!("unknown property '{}'", other))),
            }
        }
        for ip in wants {
            if except.contains(&ip) {
                continue;
            }
            let s = ip.to_string();
            if !all.contains(&s) {
                all.push(s);
            }
        }
    }
    if all.is_empty() {
        return Err(c.errf("no addresses to bind to after applying exceptions"));
    }
    c.config.listen_hosts = all;
    Ok(())
}

/// (interface name, address) pairs from getifaddrs.
#[cfg(unix)]
pub fn interfaces() -> Vec<(String, IpAddr)> {
    let mut out = Vec::new();
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return out;
        }
        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_addr.is_null() {
                let name = std::ffi::CStr::from_ptr(ifa.ifa_name).to_string_lossy().to_string();
                let sa = &*ifa.ifa_addr;
                match sa.sa_family as i32 {
                    libc::AF_INET => {
                        let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                        let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                        out.push((name, IpAddr::V4(ip)));
                    }
                    libc::AF_INET6 => {
                        let sin6 = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                        let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                        out.push((name, IpAddr::V6(ip)));
                    }
                    _ => {}
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    out
}

#[cfg(not(unix))]
pub fn interfaces() -> Vec<(String, IpAddr)> {
    Vec::new()
}
