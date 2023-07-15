#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(147947);
  script_version("1.1");

  script_name(english:"DNS over TLS Server Detection");
  script_summary(english:"Detects a running name server over TLS");

  script_set_attribute(attribute:"synopsis", value:"A DNS server is listening on the remote host over TLS.");
  script_set_attribute(attribute:"description", value:
"The remote service is a Domain Name System (DNS) server, running over TLS,
which provides a mapping between hostnames and IP addresses.");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/DNS_over_TLS");
  script_set_attribute(attribute:"solution", value:
"Disable this service if it is not needed or restrict access to
internal hosts only if the service is available externally.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"DNS");

  script_dependencies("find_service.nasl");
  script_require_keys("Transport/SSL/853");
  script_require_ports(853);

  exit(0);
}

#
# We ask the nameserver to resolve 127.0.0.1
#
include("dns_func.inc");
include("byte_func.inc");

dns["transaction_id"] = rand() % 65535;
dns["flags"]	        = 0x0010;
dns["q"]	            = 1;

packet = mkdns(dns:dns, query:mk_query(txt:dns_str_to_query_txt("1.0.0.127.IN-ADDR.ARPA"),
                                       type:DNS_QTYPE_PTR,
                                       class:DNS_QCLASS_IN));

dns_over_tls_port = 853;

if (!get_port_state(dns_over_tls_port)) audit(AUDIT_PORT_CLOSED, dns_over_tls_port);

soc = open_sock_tcp(dns_over_tls_port);

if (!soc) audit(AUDIT_SOCK_FAIL, dns_over_tls_port);

req = mkword(strlen(packet)) + packet;
send(socket:soc, data:req);
r = recv(socket:soc, length:2, min:2);

if (strlen(r) == 2)
{
  len = getword(blob:r, pos:0);
  if (len > 128) len = 128;
  r = recv(socket:soc, length:len, min:len);

  if (strlen(r) > 3)
  {
    flags = ord(r[2]);
    if (flags & 0x80)
    {
      replace_kb_item(name:"DNS+TLS/tcp/" + dns_over_tls_port, value:TRUE);
      register_service(port:dns_over_tls_port, proto:"dns");
      report = "Service on port " + dns_over_tls_port + " responded to a DNS query with a DNS response packet.";
      security_report_v4(port:dns_over_tls_port, severity:SECURITY_NOTE, extra:report);
      exit(0);
    }
  }
}

audit(AUDIT_NOT_LISTEN, "DNS", dns_over_tls_port);

