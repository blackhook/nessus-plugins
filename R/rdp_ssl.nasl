#
# (C) Tenable Network Security, Inc.
#
#

include("compat.inc");

if (description)
{
  script_id(64814);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_name(english:"Terminal Services Use SSL/TLS");
  script_summary(english:"Checks if remote Terminal Services uses SSL/TLS");

  script_set_attribute(attribute:"synopsis", value:"The remote Terminal Services use SSL/TLS.");
  script_set_attribute(attribute:"description", value:"The remote Terminal Services is configured to use SSL/TLS.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:remote_desktop_protocol");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Misc.");

  script_dependencies("windows_terminal_services.nasl");
  script_exclude_keys("global_settings/disable_test_ssl_based_services");
  script_require_ports("Services/msrdp", 3389);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("x509_func.inc");

if (get_kb_item("global_settings/disable_test_ssl_based_services"))
  exit(1, "Not testing SSL based services per user config.");

RDP_NEG_REQ     = 1;
RDP_NEG_RSP     = 2;
RDP_NEG_ERR     = 3;

SEC_PROTO_RDP       = 0;  # standard RDP security protocol
SEC_PROTO_SSL       = 1;  # TLS version 1
SEC_PROTO_HYBRID    = 2;  # Network Level Authentication (NLA), which also uses SSL

port = get_service(svc:'msrdp', default:3389, exit_on_fail:TRUE);
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

s = open_sock_tcp(port, transport: ENCAPS_IP);
if(! s) audit(AUDIT_SOCK_FAIL, port,'TCP');

s = rdp_starttls(socket:s);
if(! s) audit(AUDIT_RESP_BAD, port,'TCP', "StartTLS failed.");

#
# RDP does support STARTTLS-style SSL
#
set_kb_item(name:"rdp/"+port+"/starttls", value:TRUE);

set_byte_order(BYTE_ORDER_BIG_ENDIAN);
# Get and process the SSL certificate from the RDP server
cert = get_server_cert(port: port, encaps:COMPAT_ENCAPS_TLSv12, socket:s, encoding:"der");
if(isnull(cert))
{
  close(s);
  s = open_sock_tcp(port, transport: ENCAPS_IP);
  if(! s) audit(AUDIT_SOCK_FAIL, port, 'TCP');
  s = rdp_starttls(socket:s);
  if(! s) audit(AUDIT_SOCK_FAIL, port, 'TCP', "StartTLS failed on 2nd attempt.");
  cert = get_server_cert(port: port, encaps:ENCAPS_TLSv1, socket:s, encoding:"der");
}

close(s);
if (isnull(cert)) exit(1, "Failed to read the certificate for the service listening on port "+port+".");

cert = parse_der_cert(cert:cert);
if (isnull(cert)) exit(1, "Failed to parse the certificate from the service listening on port "+port+".");

report = dump_certificate(cert:cert);
if (!report) exit(1, "Failed to dump the certificate from the service listening on port "+port+".");

if (report_verbosity > 0) security_note(port:port, extra:report);
else security_note(port);
