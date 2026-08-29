//! `geoip DBFILE { edns-subnet }` — looks the client up in a MaxMind
//! City/Country database and publishes the result as metadata labels:
//! `geoip/city/name`, `geoip/country/code`, `geoip/country/name`,
//! `geoip/country/is_in_european_union`, `geoip/continent/code`,
//! `geoip/continent/name`, `geoip/latitude`, `geoip/longitude`,
//! `geoip/timezone`, `geoip/postalcode`. Requires the `metadata` plugin.

use crate::plugin::{Controller, DnsResult, Handler, Next, Request};
use async_trait::async_trait;
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use maxminddb::geoip2;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

pub struct GeoIp {
    reader: maxminddb::Reader<Vec<u8>>,
    edns_subnet: bool,
}

impl GeoIp {
    fn client_ip(&self, req: &Request) -> IpAddr {
        if self.edns_subnet {
            if let Some(e) = req.msg.edns() {
                if let Some(EdnsOption::Subnet(cs)) = e.option(EdnsCode::Subnet) {
                    return cs.addr();
                }
            }
        }
        req.ip()
    }
}

#[async_trait]
impl Handler for GeoIp {
    fn name(&self) -> &'static str {
        "geoip"
    }

    fn metadata(&self, req: &mut Request) {
        let ip = self.client_ip(req);
        let Ok(city) = self.reader.lookup::<geoip2::City>(ip) else { return };
        let md = &mut req.metadata;
        if let Some(c) = &city.city {
            if let Some(n) = c.names.as_ref().and_then(|n| n.get("en")) {
                md.set_static("geoip/city/name", n.to_string());
            }
        }
        if let Some(c) = &city.country {
            if let Some(code) = c.iso_code {
                md.set_static("geoip/country/code", code.to_string());
            }
            if let Some(n) = c.names.as_ref().and_then(|n| n.get("en")) {
                md.set_static("geoip/country/name", n.to_string());
            }
            md.set_static("geoip/country/is_in_european_union", c.is_in_european_union.unwrap_or(false).to_string());
        }
        if let Some(c) = &city.continent {
            if let Some(code) = c.code {
                md.set_static("geoip/continent/code", code.to_string());
            }
            if let Some(n) = c.names.as_ref().and_then(|n| n.get("en")) {
                md.set_static("geoip/continent/name", n.to_string());
            }
        }
        if let Some(l) = &city.location {
            if let Some(lat) = l.latitude {
                md.set_static("geoip/latitude", format!("{:.6}", lat));
            }
            if let Some(lon) = l.longitude {
                md.set_static("geoip/longitude", format!("{:.6}", lon));
            }
            if let Some(tz) = l.time_zone {
                md.set_static("geoip/timezone", tz.to_string());
            }
        }
        if let Some(p) = &city.postal {
            if let Some(code) = p.code {
                md.set_static("geoip/postalcode", code.to_string());
            }
        }
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        next.serve(req).await
    }
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut n = 0;
    while c.next() {
        n += 1;
        if n > 1 {
            return Err(c.errf("plugin/geoip: this plugin can only be used once per Server Block"));
        }
        let args = c.remaining_args_until_brace();
        if args.len() != 1 {
            return Err(c.errf("geoip DBFILE expected"));
        }
        let path = if std::path::Path::new(&args[0]).is_absolute() { PathBuf::from(&args[0]) } else { c.config.root.join(&args[0]) };
        let mut edns_subnet = false;
        while c.next_block() {
            match c.val() {
                "edns-subnet" => edns_subnet = true,
                o => return Err(c.errf(format!("unknown property '{}'", o))),
            }
        }
        let reader = maxminddb::Reader::open_readfile(&path).map_err(|e| c.errf(format!("failed to open database file {}: {}", path.display(), e)))?;
        let ty = reader.metadata.database_type.clone();
        if !ty.contains("City") && !ty.contains("Country") {
            return Err(c.errf(format!("database {} is of unsupported type {}", path.display(), ty)));
        }
        c.add_plugin(Arc::new(GeoIp { reader, edns_subnet }));
    }
    Ok(())
}
