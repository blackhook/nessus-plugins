#TRUSTED 7533619e4c81ea50011a8950ca3f15222476bbc4251910386285b5e7b08a55bcbe69adeac28fd80f063163a5023152937176125fe2f4b4391d8658c111a35b4d5f086af01f953931b12eced814338e8512381d0bd4ba7ea55e1e2b74d400dd17ca1958b7e8e64d1d41a16e306594990eb895e34d9a6a8598b308ccb4580f18474e3bbc929022a00b01ba96530290b4a2c352fb0dfc1879817cae668d1842a9a8278666bccf878e35e30d79d6c3300f3c2b6dc927241dd7c9619d523fc745dd79f8a716ae9e65c755443536e0e9c146496789ffbcbddc4fe9e87b03c689256967b9cf1ec185eeec698d4f3c7366905344c95569b0096cd476ab745686555deec866687985dff11a0e23d1c1fa066aebaa5b94b7dabfcb1c75f6a4c11a8a5e5e2125ae95cf0e110a254ec0247886ffc8875497f85c81a48c8404da5433570a777a6814609b2f5e6d00079493ef20253cb756dc6d908da82810972b3989494e6e9daceed01065b1395d29ef9bede1bae91cef821cfbbb1339d36dd881f14ac58e2668187eda8f3b6a7ee0db72fe92efacaae11e6ba31ae021d32aff820a381b75f09466597f5cf96350cdc2571d4e9d7028b8613ad9b66836eba4dc472403237be9194aa5d149e549ba4c3554e097c710b3c2b7786292a563db808ff3194c024fc4a9dd8d3425861d40615408a3b85ea1f8c64435ab9e85724f0a114b99b00097c4
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("socket_redo_ssl_handshake")) exit(1, "socket_redo_ssl_handshake() is not defined.");

include("compat.inc");

if (description)
{
  script_id(42880);
  script_version("1.48");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/12");

  script_cve_id("CVE-2009-3555");
  script_bugtraq_id(36935);
  script_xref(name:"CERT", value:"120541");

  script_name(english:"SSL / TLS Renegotiation Handshakes MiTM Plaintext Data Injection");
  script_summary(english:"Tries to renegotiate an SSL connection");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote service allows insecure renegotiation of TLS / SSL
connections."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote service encrypts traffic using TLS / SSL but allows a client
to insecurely renegotiate the connection after the initial handshake.
An unauthenticated, remote attacker may be able to leverage this issue
to inject an arbitrary amount of plaintext into the beginning of the
application protocol stream, which could facilitate man-in-the-middle
attacks if the service assumes that the sessions before and after
renegotiation are from the same 'client' and merges them at the
application layer."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.ietf.org/mail-archive/web/tls/current/msg03948.html");
  script_set_attribute(attribute:"see_also", value:"http://www.g-sec.lu/practicaltls.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/rfc5746");
  script_set_attribute(attribute:"solution", value:"Contact the vendor for specific patch information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2009-2020 Tenable Network Security, Inc.");

  script_dependencies("ssl_supported_versions.nasl");
  script_require_keys("SSL/Supported");
  exit(0);
}


include("audit.inc");
include("byte_func.inc");
include("ftp_func.inc");
include("global_settings.inc");
include("kerberos_func.inc");
include("ldap_func.inc");
include("misc_func.inc");
include("nntp_func.inc");
include("smtp_func.inc");
include("ssl_funcs.inc");
include("telnet2_func.inc");
include("rsync.inc");


# nb: SSLv2 doesn't support renegotiation.
encapss = make_list(ENCAPS_TLSv1, ENCAPS_SSLv3);

# Certain SSL implementations, when sent a ClientHello with
# a number of ciphers past some threshold, simply close the
# socket. We'll try connecting with the default list that
# OpenSSL uses.
cipherspec = "";
cipherspec += raw_string(0xc0, 0x14);
cipherspec += raw_string(0xc0, 0x0a);
cipherspec += raw_string(0x00, 0x39);
cipherspec += raw_string(0x00, 0x38);
cipherspec += raw_string(0x00, 0x88);
cipherspec += raw_string(0x00, 0x87);
cipherspec += raw_string(0xc0, 0x0f);
cipherspec += raw_string(0xc0, 0x05);
cipherspec += raw_string(0x00, 0x35);
cipherspec += raw_string(0x00, 0x84);
cipherspec += raw_string(0xc0, 0x12);
cipherspec += raw_string(0xc0, 0x08);
cipherspec += raw_string(0x00, 0x16);
cipherspec += raw_string(0x00, 0x13);
cipherspec += raw_string(0xc0, 0x0d);
cipherspec += raw_string(0xc0, 0x03);
cipherspec += raw_string(0x00, 0x0a);
cipherspec += raw_string(0xc0, 0x13);
cipherspec += raw_string(0xc0, 0x09);
cipherspec += raw_string(0x00, 0x33);
cipherspec += raw_string(0x00, 0x32);
cipherspec += raw_string(0x00, 0x9a);
cipherspec += raw_string(0x00, 0x99);
cipherspec += raw_string(0x00, 0x45);
cipherspec += raw_string(0x00, 0x44);
cipherspec += raw_string(0xc0, 0x0e);
cipherspec += raw_string(0xc0, 0x04);
cipherspec += raw_string(0x00, 0x2f);
cipherspec += raw_string(0x00, 0x96);
cipherspec += raw_string(0x00, 0x41);
cipherspec += raw_string(0x00, 0x07);
cipherspec += raw_string(0xc0, 0x11);
cipherspec += raw_string(0xc0, 0x07);
cipherspec += raw_string(0xc0, 0x0c);
cipherspec += raw_string(0xc0, 0x02);
cipherspec += raw_string(0x00, 0x05);
cipherspec += raw_string(0x00, 0x04);
cipherspec += raw_string(0x00, 0x15);
cipherspec += raw_string(0x00, 0x12);
cipherspec += raw_string(0x00, 0x09);
cipherspec += raw_string(0x00, 0x14);
cipherspec += raw_string(0x00, 0x11);
cipherspec += raw_string(0x00, 0x08);
cipherspec += raw_string(0x00, 0x06);
cipherspec += raw_string(0x00, 0x03);

# This value isn't actually a cipher, instead it signals to
# the server that the client supports secure renegotiation.
cipherspec += raw_string(0x00, 0xff);


get_kb_item_or_exit("SSL/Supported");

# Get a port to operate on, forking for each one.
port = get_ssl_ports(fork:TRUE);
if (isnull(port))
  exit(1, "The host does not appear to have any SSL-based services.");

# Find out if the port is open.
if (!get_port_state(port))
  exit(0, "Port " + port + " is not open.");

# These are status flags to customize the audit trail depending on the
# behaviour of the server.
secure = 0;
negotiated = FALSE;

report = "";
foreach encaps (encapss)
{
  # Create a Client Hello record.
  if (encaps == ENCAPS_SSLv3)
  {
    ssl_name = "SSLv3";
    ssl_ver = raw_string(0x03, 0x00);
  }
  else if (encaps == ENCAPS_TLSv1)
  {
    ssl_name = "TLSv1";
    ssl_ver = raw_string(0x03, 0x01);
  }

  helo = client_hello(
    version    : ssl_ver,
    cipherspec : cipherspec,
    v2hello    : FALSE
  );

  # Open a socket without encapsulation.
  sock = open_sock_ssl(port);
  if (!sock)
    exit(1, "open_sock_ssl() returned NULL for port " + port + ".");

  # Try to negotiate initial SSL connection.
  send(socket:sock, data:helo);
  recs = recv_ssl(socket:sock);
  close(sock);
  if (isnull(recs)) continue;

  # Check for the secure renegotiation extension.
  rec = ssl_find(
    blob:recs,
    "content_type", SSL3_CONTENT_TYPE_HANDSHAKE,
    "handshake_type", SSL3_HANDSHAKE_TYPE_SERVER_HELLO
  );
  if( isnull(rec))
    continue;

  negotiated = TRUE;
  count = rec["extension_renegotiation_info_renegotiated_connection"];
  if (!isnull(count))
  {
    if (count != 0)
    {
      report +=
        '\n' + ssl_name + ' appears to support secure renegotiation, but' +
        '\nrenegotiated_connection has a value of ' + count + ' instead of zero.' +
        '\n';
    }
    else
    {
      secure++;
    }
    continue;
  }

  # Open a socket with encapsulation.
  sock = open_sock_ssl(port, encaps:encaps);
  if (!sock) continue;
  negotiated = TRUE;

  # Try to renegotiate SSL connection.
  sock = socket_redo_ssl_handshake(sock);
  if (!sock) continue;

  # Some SSL implementations will drop the connection upon 
  # the second successful handhake, as a mitigation.
  # Here we try a third handshake to test such case.
  sock = socket_redo_ssl_handshake(sock);
  if (!sock) continue;

  close(sock);

  # SSL implementation allows insecure renegotiation.
  report +=
    '\n' + ssl_name + ' supports insecure renegotiation.' +
    '\n';
}

if (report == "")
{
  if (!negotiated)
    msg = "rejected every attempt to negotiate";
  else if (secure == max_index(encapss))
    msg = "does not support insecure renegotiation";
  else
    msg = "rejected every attempt to renegotiate";

  exit(0, "Port " + port + " " + msg + ".");
}

security_warning(port:port, extra:report);
