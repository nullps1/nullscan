//! Plain-English finding copy, keyed by port and then by service name.
//!
//! Edit this table to change client-facing wording. The generic fallback is
//! used when neither the port nor the service name matches.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effort {
    Quick,
    Moderate,
    NeedsIt,
}

impl Effort {
    pub fn label(self) -> &'static str {
        match self {
            Effort::Quick => "Quick",
            Effort::Moderate => "Moderate",
            Effort::NeedsIt => "Needs IT",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Who {
    You,
    ItProvider,
    Vendor,
}

impl Who {
    pub fn label(self) -> &'static str {
        match self {
            Who::You => "You",
            Who::ItProvider => "IT provider",
            Who::Vendor => "Vendor",
        }
    }
}

pub struct PlaybookEntry {
    pub ports: &'static [u16],
    pub services: &'static [&'static str],
    pub plain_name: &'static str,
    pub what: &'static str,
    pub why: &'static str,
    pub steps: &'static [&'static str],
    pub effort: Effort,
    pub who: Who,
}

const ENTRIES: &[PlaybookEntry] = &[
    PlaybookEntry {
        ports: &[3389],
        services: &["rdp", "remote desktop"],
        plain_name: "Remote Desktop",
        what: "Remote Desktop lets someone control a computer from anywhere, and right now anyone on the internet can reach the login screen.",
        why: "This is one of the most common ways ransomware gets in. Attackers try passwords automatically, 24/7.",
        steps: &[
            "Close port 3389 on the firewall.",
            "Use a VPN or a remote-access tool with multi-factor login instead.",
        ],
        effort: Effort::Quick,
        who: Who::ItProvider,
    },
    PlaybookEntry {
        ports: &[445, 139],
        services: &["smb"],
        plain_name: "Windows file sharing",
        what: "Windows file sharing is how office computers share folders. Right now that share can be reached from the internet.",
        why: "Attackers use exposed file sharing to steal files and to spread ransomware from one computer to the next.",
        steps: &[
            "Block file sharing from the internet.",
            "Keep shares on the private network, and reach them through a VPN.",
        ],
        effort: Effort::Quick,
        who: Who::ItProvider,
    },
    PlaybookEntry {
        ports: &[23],
        services: &["telnet"],
        plain_name: "Telnet remote login",
        what: "Telnet is an old remote login, and it sends the password where anyone on the path can read it.",
        why: "Automated scans look for Telnet all day. A guessed or captured password is full control of the device.",
        steps: &[
            "Turn Telnet off.",
            "If remote login is still required, use SSH with keys, or a VPN.",
        ],
        effort: Effort::Quick,
        who: Who::ItProvider,
    },
    PlaybookEntry {
        ports: &[5900],
        services: &["vnc"],
        plain_name: "VNC remote screen",
        what: "VNC shows a computer's screen to whoever can open the port.",
        why: "These screens are often protected by a short password, or by none. Attackers watch them and take over.",
        steps: &[
            "Close port 5900 on the firewall.",
            "If a remote screen is required, put it behind a VPN and multi-factor login.",
        ],
        effort: Effort::Quick,
        who: Who::ItProvider,
    },
    PlaybookEntry {
        ports: &[3306],
        services: &["mysql"],
        plain_name: "MySQL database",
        what: "MySQL is a database. Its login port is reachable from the internet.",
        why: "A database on the public internet is a direct path to business and customer data.",
        steps: &[
            "Block port 3306 from the internet.",
            "Allow the database only from the application servers that need it.",
        ],
        effort: Effort::Moderate,
        who: Who::ItProvider,
    },
    PlaybookEntry {
        ports: &[5432],
        services: &["postgres"],
        plain_name: "PostgreSQL database",
        what: "PostgreSQL is a database. Its login port is reachable from the internet.",
        why: "A database on the public internet is a direct path to business and customer data.",
        steps: &[
            "Block port 5432 from the internet.",
            "Allow the database only from the application servers that need it.",
        ],
        effort: Effort::Moderate,
        who: Who::ItProvider,
    },
    PlaybookEntry {
        ports: &[1433],
        services: &["mssql"],
        plain_name: "SQL Server database",
        what: "SQL Server is a database. Its login port is reachable from the internet.",
        why: "A database on the public internet is a direct path to business and customer data.",
        steps: &[
            "Block port 1433 from the internet.",
            "Allow the database only from the application servers that need it.",
        ],
        effort: Effort::Moderate,
        who: Who::ItProvider,
    },
    PlaybookEntry {
        ports: &[1521],
        services: &["oracle"],
        plain_name: "Oracle database",
        what: "Oracle Database is answering on the internet.",
        why: "A database on the public internet is a direct path to business and customer data.",
        steps: &[
            "Block port 1521 from the internet.",
            "Allow the database only from the application servers that need it.",
        ],
        effort: Effort::Moderate,
        who: Who::ItProvider,
    },
    PlaybookEntry {
        ports: &[27017],
        services: &["mongo"],
        plain_name: "MongoDB database",
        what: "MongoDB is a database. Its port is reachable from the internet.",
        why: "Exposed MongoDB servers are frequently copied or wiped by automated attacks.",
        steps: &[
            "Block port 27017 from the internet.",
            "Turn on authentication and allow the database only from application servers.",
        ],
        effort: Effort::Moderate,
        who: Who::ItProvider,
    },
    PlaybookEntry {
        ports: &[6379],
        services: &["redis"],
        plain_name: "Redis data store",
        what: "Redis is an in-memory data store. Its port is reachable from the internet.",
        why: "Redis often has no password. Attackers use an open Redis to steal data or to get a foothold on the server.",
        steps: &[
            "Block port 6379 from the internet.",
            "Bind Redis to the private network and require a password.",
        ],
        effort: Effort::Quick,
        who: Who::ItProvider,
    },
    PlaybookEntry {
        ports: &[9200],
        services: &["elasticsearch"],
        plain_name: "Elasticsearch",
        what: "Elasticsearch is a search database. Its port is reachable from the internet.",
        why: "An open search database often holds logs, customer text, or credentials, and it is a common theft target.",
        steps: &[
            "Block port 9200 from the internet.",
            "Require login and allow the database only from the systems that query it.",
        ],
        effort: Effort::NeedsIt,
        who: Who::ItProvider,
    },
    PlaybookEntry {
        ports: &[21],
        services: &["ftp"],
        plain_name: "File transfer (FTP)",
        what: "FTP moves files with an old protocol that sends the username and password in the clear.",
        why: "Anyone who can watch the connection can read the login. Exposed FTP is also used to park stolen files.",
        steps: &[
            "Turn FTP off if it is not required.",
            "Use SFTP or a private file share instead of FTP.",
        ],
        effort: Effort::Moderate,
        who: Who::ItProvider,
    },
    PlaybookEntry {
        ports: &[110],
        services: &["pop3"],
        plain_name: "Mailbox login (POP)",
        what: "This mailbox login can send the password without encryption.",
        why: "Anyone who can watch the connection can read the mailbox password and the mail.",
        steps: &[
            "Turn off plain POP.",
            "Use the encrypted mailbox ports, or a modern host with multi-factor login.",
        ],
        effort: Effort::Quick,
        who: Who::ItProvider,
    },
    PlaybookEntry {
        ports: &[143],
        services: &["imap"],
        plain_name: "Mailbox login (IMAP)",
        what: "This mailbox login can send the password without encryption.",
        why: "Anyone who can watch the connection can read the mailbox password and the mail.",
        steps: &[
            "Turn off plain IMAP.",
            "Use the encrypted mailbox ports, or a modern host with multi-factor login.",
        ],
        effort: Effort::Quick,
        who: Who::ItProvider,
    },
    PlaybookEntry {
        ports: &[22],
        services: &["ssh"],
        plain_name: "Secure shell login",
        what: "SSH is a remote login for servers. This one answers from the internet, so anyone can try the login screen.",
        why: "Password guessing against SSH never stops. A weak password or old software is enough for a break-in.",
        steps: &[
            "Allow SSH only from known addresses, or put it behind a VPN.",
            "Turn off password login and use keys plus multi-factor login.",
            "Install updates if the banner shows old software.",
        ],
        effort: Effort::Moderate,
        who: Who::ItProvider,
    },
    PlaybookEntry {
        ports: &[161],
        services: &["snmp"],
        plain_name: "Network management (SNMP)",
        what: "SNMP lets someone ask a device for its names, addresses, and status.",
        why: "The default password is often still \"public\", which hands over a map of the network.",
        steps: &[
            "Block SNMP from the internet.",
            "If a monitoring tool needs it, allow only that tool and change the community string.",
        ],
        effort: Effort::Quick,
        who: Who::ItProvider,
    },
    PlaybookEntry {
        ports: &[8080, 8443, 10000],
        services: &["admin", "webmin", "cpanel"],
        plain_name: "Admin web page",
        what: "A management web page is reachable from the internet.",
        why: "Admin pages are a favorite target. One guessed password can hand over the device or the site.",
        steps: &[
            "Take the admin page off the public internet.",
            "Reach it through a VPN, and turn on multi-factor login.",
        ],
        effort: Effort::Quick,
        who: Who::ItProvider,
    },
    PlaybookEntry {
        ports: &[80],
        services: &["http"],
        plain_name: "Web site (unencrypted)",
        what: "A web site is answering on the plain, unencrypted web port.",
        why: "Anything typed there, including passwords, can be read on the network path. Old web software is a common way in.",
        steps: &[
            "Send visitors to the encrypted site and close plain HTTP if you do not need it.",
            "Remove version details from the banner, and install updates when a possible issue is listed.",
        ],
        effort: Effort::Moderate,
        who: Who::ItProvider,
    },
    PlaybookEntry {
        ports: &[443],
        services: &["https", "tls", "ssl"],
        plain_name: "Encrypted web site",
        what: "An encrypted web site is answering. That is normal when the site is meant to be public.",
        why: "The port itself is expected. The risk is old software, or a banner that gives the version away.",
        steps: &[
            "Confirm the site should be public.",
            "Install updates when a possible issue is listed, and hide version numbers in the banner.",
        ],
        effort: Effort::Moderate,
        who: Who::ItProvider,
    },
    PlaybookEntry {
        ports: &[25, 587, 465],
        services: &["smtp"],
        plain_name: "Mail server",
        what: "A mail server is answering. That is normal for a company that receives its own mail.",
        why: "Mail servers are expected on a known mail host. An old version can still be abused to send spam or to break in.",
        steps: &[
            "Confirm this host is supposed to receive mail.",
            "Keep the mail software updated, and make sure login is encrypted.",
        ],
        effort: Effort::Moderate,
        who: Who::Vendor,
    },
    PlaybookEntry {
        ports: &[53],
        services: &["dns"],
        plain_name: "DNS",
        what: "A DNS service is answering. It translates names into addresses.",
        why: "An open DNS resolver can be abused to attack other people, and a version banner shows what to aim at.",
        steps: &[
            "Allow DNS queries only from your own networks unless this is a public resolver on purpose.",
            "Hide version numbers and install updates.",
        ],
        effort: Effort::Moderate,
        who: Who::ItProvider,
    },
];

const GENERIC: PlaybookEntry = PlaybookEntry {
    ports: &[],
    services: &[],
    plain_name: "Unrecognized service",
    what: "An unrecognized service is reachable from the internet. Confirm it's needed; if not, close it.",
    why: "Anything that answers on the public internet can be scanned and used as a way in.",
    steps: &[
        "Confirm the service is supposed to be public.",
        "If it is not needed, close the port on the firewall.",
        "If it is needed, limit who can reach it and keep it updated.",
    ],
    effort: Effort::Moderate,
    who: Who::You,
};

fn service_key_matches(service: &str, key: &str) -> bool {
    // "https" contains "http", but it is not the unencrypted web entry.
    if key == "http" {
        return service == "http" || service.starts_with("http ") || service.starts_with("http/");
    }
    service.contains(key)
}

pub fn lookup(port: u16, service: Option<&str>) -> &'static PlaybookEntry {
    if let Some(entry) = ENTRIES.iter().find(|entry| entry.ports.contains(&port)) {
        return entry;
    }
    if let Some(service) = service {
        let service = service.to_ascii_lowercase();
        if let Some(entry) = ENTRIES.iter().find(|entry| {
            entry
                .services
                .iter()
                .any(|key| service_key_matches(&service, key))
        }) {
            return entry;
        }
    }
    &GENERIC
}

pub fn title_for(entry: &PlaybookEntry) -> String {
    format!("{} open to the internet", entry.plain_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_ports_have_plain_names() {
        let expected = [
            (3389, "Remote Desktop"),
            (445, "Windows file sharing"),
            (23, "Telnet remote login"),
            (5900, "VNC remote screen"),
            (3306, "MySQL database"),
            (5432, "PostgreSQL database"),
            (1433, "SQL Server database"),
            (1521, "Oracle database"),
            (27017, "MongoDB database"),
            (6379, "Redis data store"),
            (9200, "Elasticsearch"),
        ];
        for (port, name) in expected {
            assert_eq!(lookup(port, None).plain_name, name, "port {port}");
        }
    }

    #[test]
    fn unknown_port_uses_the_generic_sentence() {
        let entry = lookup(4242, Some("mystery"));
        assert_eq!(entry.plain_name, "Unrecognized service");
        assert!(entry
            .what
            .contains("Confirm it's needed; if not, close it."));
    }

    #[test]
    fn service_name_matches_when_the_port_is_unusual() {
        assert_eq!(lookup(2222, Some("SSH")).plain_name, "Secure shell login");
        assert_eq!(lookup(3307, Some("MySQL")).plain_name, "MySQL database");
        assert_eq!(lookup(8443, Some("HTTPS")).plain_name, "Admin web page");
        assert_eq!(lookup(444, Some("HTTPS")).plain_name, "Encrypted web site");
    }

    #[test]
    fn titles_follow_the_template() {
        let entry = lookup(3389, Some("RDP"));
        assert_eq!(title_for(entry), "Remote Desktop open to the internet");
    }
}
