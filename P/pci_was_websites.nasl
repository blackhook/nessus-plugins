#
# (C) Tenable Network Security, Inc.
include('compat.inc');

if (description)
{
  script_id(121348);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/24");

  script_name(english:"WAS Target Discovery for PCI");
  script_summary(english:"Find www ports and their encapsulation.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin discovers web sites on a scanned system for PCI WAS scanning.");
  script_set_attribute(attribute:"description", value:
"This plugin discovers web sites on a scanned system.");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_dependencies("dont_scan_printers.nasl", "dont_scan_printers2.nasl", "dont_scan_ot.nasl");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Settings/PCI_DSS");
  script_exclude_keys("Host/dead");
  script_timeout(0);
  exit(0);
}

include('global_settings.inc');
include('audit.inc');
include('byte_func.inc');
include('ssl_funcs.inc');
include('http.inc');

# skip checking this in command line mode so flatline tests will work
if (!isnull(get_preference("plugins_folder")))
{
  var policy_name = get_preference("@internal@policy_name");
  if(policy_name != "PCI Discovery")
    exit(0, "This plugin only runs under the PCI discovery policy.");
}

if (!get_kb_item("Settings/PCI_DSS"))
  audit(AUDIT_PCI);

if(get_kb_item("Host/dead"))
  audit(AUDIT_HOST_NOT, "alive or was excluded from scanning by policy.");

var port_protos = {};

var ssl_protos = [COMPAT_ENCAPS_TLSv12, COMPAT_ENCAPS_TLSv11, ENCAPS_TLSv1, ENCAPS_SSLv3, ENCAPS_SSLv2];
var proto_ver = {
  0x303: COMPAT_ENCAPS_TLSv12,
  0x302: COMPAT_ENCAPS_TLSv11,
  0x301: ENCAPS_TLSv1
};

function open_negotiated_socket(port, ssl)
{
  local_var soc, encaps, v2hello, npn, helo, exts, recs;
  local_var host, ssl_ver, rec;

  if(port_protos[port])
    return open_sock_tcp(port, transport:port_protos[port]);

  soc = open_sock_tcp(port, transport:ENCAPS_IP);
  if(!ssl || !soc) return soc;

  # This is the Next Protocol Negotiation extension that asks the server to list
  # its supported protocols.
  npn =
    mkword(13172) + # Extension type
    mkword(0);      # Extension length

  # Add on an SNI extension if it makes sense to
  host = get_host_name();
  if (host != get_host_ip() && host != NULL)
    npn += tls_ext_sni(hostname:host);

  foreach encaps(ssl_protos)
  {
    v2hello = FALSE;

    #Create a minimal client_hello to detect SSL/TLS support
    if(encaps == ENCAPS_SSLv2) v2hello = TRUE;

    if (encaps == ENCAPS_SSLv2) ssl_ver = raw_string(0x00, 0x02);
    else if (encaps == ENCAPS_SSLv3) ssl_ver = raw_string(0x03, 0x00);
    else if (encaps == ENCAPS_TLSv1) ssl_ver = raw_string(0x03, 0x01);
    else if (encaps == COMPAT_ENCAPS_TLSv11) ssl_ver = raw_string(0x03, 0x02);
    else if (encaps == COMPAT_ENCAPS_TLSv12) ssl_ver = raw_string(0x03, 0x03);

    if(encaps >= ENCAPS_TLSv1) exts = npn;
    if(encaps == COMPAT_ENCAPS_TLSv12)
      exts += tls_ext_ec() + tls_ext_ec_pt_fmt() + tls_ext_sig_algs();

    # Create a ClientHello record.
    helo = client_hello(
      version       : ssl_ver,
      v2hello       : v2hello,
      extensions    : exts
    );

    # Send the ClientHello record.
    send(socket:soc, data:helo);

    recs = recv_ssl_recs(socket:soc);
    close(soc);

    # Find and parse the ServerHello record.
    if(encaps == ENCAPS_SSLv2)
    {
      rec = ssl_find(
        blob:recs,
        "content_type", SSL2_CONTENT_TYPE_SERVER_HELLO
      );
    }
    else
    {
      rec = ssl_find(
        blob:recs,
        "content_type", SSL3_CONTENT_TYPE_HANDSHAKE,
        "handshake_type", SSL3_HANDSHAKE_TYPE_SERVER_HELLO
      );
    }

    if(rec)
    {
      if(encaps >= ENCAPS_TLSv1)
        encaps = proto_ver[rec["version"]];

      port_protos[port] = encaps;

      soc = open_sock_tcp(port, transport:port_protos[port]);
      return soc;
    }

    #Open a socket for the next iteration of the encapsulation loop
    soc = open_sock_tcp(port, transport:ENCAPS_IP);
    if(!soc) return 0;
  }

  close(soc);
  return 0;
}


function http_is_not_dead(port, ssl)
{
  local_var soc, soc2, req, rq, code, i, verb, encaps;
  var verbs = ['GET', 'HEAD', 'TRACE', 'POST'];
  encaps = NULL;

  soc = open_negotiated_socket(port:port, ssl:ssl);
  if(! soc) return 0;

  foreach verb(verbs)
  {
    rq = http_mk_req(method: verb, port: port, item: '/');
    req = http_mk_buffer_from_req(req: rq);

    send(socket:soc, data:req);
    code = recv_line(socket:soc, length:1024);

    if(!code) continue;

    #Any response with an HTTP status line is good enough.
    if(preg(pattern: "^HTTP/.* \d{3}", string: code))
    {
      close(soc);
      return 1;
    }
  }

  close(soc);
  return 0;
}

var was_targets = make_list();

var port_list = get_kb_list("Ports/tcp/*");
if(isnull(port_list)) exit(0, "No open ports found."); # No open port


var ports = make_list(keys(port_list));
var port = branch(ports);

port = int(port - "Ports/tcp/");
if (!get_tcp_port_state(port))
  audit(AUDIT_PORT_CLOSED, port);

if(http_is_not_dead(port:port))
  set_kb_item(name:"PCI_WAS_www/" + port, value:"http");

if(http_is_not_dead(port:port, ssl:TRUE))
  set_kb_item(name:"PCI_WAS_www/" + port, value:"https");

exit(0);
