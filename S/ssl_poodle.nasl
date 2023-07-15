#TRUSTED 25998a5813654de1a02985e76eefeeefdbba558916d2fcc3a55694ce9c72d490e9418c0204084346c70889132f79b50527803ce4ae771b0d2c878c0c6b16972338a3ee101e51fb23f1a618b7c336e25f22fecf450bf3ea19598a0adb27e4815276fae0ca8bcb1ceac1fb3c09d713e9357158a2fe21c992b49d86b0ed420624bffc4627185ceec04fdc7586db534880c1e3efc0287ea7d3a24aebdd66613260126b9e92dd33cfd4287f8798576fa76a0cd1f1b594f8d242620ff7b3deb2bc30a06becf3df1b6820389b15795a83814bdd80e77b3aea61526991217dc3bd076fc50fd2c9575f5e7f7f52c85c42226739474ac7365370852353d8f13d0285bbf138c595a1484b65d94a9306222c8a4a8b5f6e7cdf0ea66422ca81ca0d6eebcd861406e91bfce08cd89056b8420a1f262f320ae91d78dacec471181ed99b1ea9f40d8620d792164b4f822589ef53f67865245c25301f9662abeaf5c85558c51ae11b530e09eca377ab07863d841be937280fdf5d6cf5b74cddd835af85de4d565a6716959f7bd18d19cfa8572d859e4e37f5f5785ba4297959da3dc9cc9acb43774168bd9e03ba8964e7deac9bc20c2acb5ee0a1784efbeff6824c703e0cbaa27f64261597bd1f7f8f2eac6d5716b6d94d3c2800a857ac1d866d40760bf68002aeb47f92255e00cf5db84f409b7349276b8abeed181f71937a16ecc35d8b72540ca6
#TRUST-RSA-SHA256 0f9b02c7aac951d16272cfc727f36d9de88dbd8efcb77538eb02b944118f381c75b2500df78f95e41334ddda7bd66c13556d7055b693aa4606c3a8bc4e11d1be3e630fe102354ab644279b8eefd4ad15b2cbd4d5582f6672fcb72c72230ccdbcef74eecb6a8d8ff5e72e840960561c7911c67ad2f4dcfd7e52131ac50fc2a39cc17b047d15c0a3c1d897f3d820332e4573f12db901d0a886155f52a49f6b3b4356ab1ab4a7cc518223297d42e94b4a269f55fb359e68c8b42433eaf07948371816674f0b93b43c331290013b5a565568e128bc65d28c5a003d6541f224c616ade0bd23304e049753faf7ad2dfaf698af6ae1119a20be0db8e8d512859f0065a7bb7e995f623cf85ae8119c1ba7187d95bcab2289f098b1a2759bf9362772da3ca242907787bd74ebde44625066706305b0e9a19077ede8686dd6bbbf9f408ce0d27f0a921bacf806d6f42afc021224c88fc74c25f48642a6c8fae9be1144434e2d0a195d90c30900ee76e5004e9cbe90c29ee52c54ae169f342787f85c3ad5523c65aa3d6b8ad841becdce7f2af8632a13b756b4ce6acb29350c899098cdb34d037d043435995c16a9dac193011e82c5a26b81b4e8f8a8ab0c8bb031fc7c604b21400cf787ab2ff2862524376f95b9dd02bb6f7716750dfb0685192e4432713e391980dacde52e1534893c95139e9538bc14fa65f2637e49d377bb8f755a6872
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(78479);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/23");

  script_cve_id("CVE-2014-3566");
  script_bugtraq_id(70574);
  script_xref(name:"CERT", value:"577193");

  script_name(english:"SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE)");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain sensitive information from the remote host
with SSL/TLS-enabled services.");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by a man-in-the-middle (MitM) information
disclosure vulnerability known as POODLE. The vulnerability is due to
the way SSL 3.0 handles padding bytes when decrypting messages
encrypted using block ciphers in cipher block chaining (CBC) mode.
MitM attackers can decrypt a selected byte of a cipher text in as few
as 256 tries if they are able to force a victim application to
repeatedly send the same data over newly created SSL 3.0 connections.

As long as a client and service both support SSLv3, a connection can
be 'rolled back' to SSLv3, even if TLSv1 or newer is supported by the
client and service.

The TLS Fallback SCSV mechanism prevents 'version rollback' attacks
without impacting legacy clients; however, it can only protect
connections when the client and service support the mechanism. Sites
that cannot disable SSLv3 immediately should enable this mechanism.

This is a vulnerability in the SSLv3 specification, not in any
particular SSL implementation. Disabling SSLv3 is the only way to
completely mitigate the vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:
"Disable SSLv3.

Services that must support SSLv3 should enable the TLS Fallback SCSV
mechanism until SSLv3 can be disabled.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3566");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2014-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssl_supported_versions.nasl", "ssl_supported_ciphers.nasl");
  script_require_keys("SSL/Supported");

  exit(0);
}

include("ftp_func.inc");
include("global_settings.inc");
include("ldap_func.inc");
include("nntp_func.inc");
include("rsync.inc");
include("smtp_func.inc");
include("telnet2_func.inc");
include("x509_func.inc");
include("audit.inc");

connection_reset = FALSE;
# Send an SSLv3 ClientHello with modified cipher suite list.
# Cipher suite list must be in the format that client_hello expects.
function send_recv_client_hello(port, cipherspec)
{
  local_var soc, rec, chello;

  soc = open_sock_ssl(port);
  if (!soc) return NULL;

  chello = client_hello(
    version:mkword(SSL_V3),
    v2hello:FALSE,
    cipherspec:cipherspec
  );
  send(socket:soc, data:chello);
  rec = recv_ssl(socket:soc, partial:TRUE);
  if (socket_get_error(soc) == ECONNRESET)
    connection_reset = TRUE;
  close(soc);

  return rec;
}

function check_fallback_scsv(port, cipherspec)
{
  local_var rec, cipher_name, kb_key;

  # Add the TLS_FALLBACK_SCSV to the list
  cipherspec += raw_string(0x56, 0x00);

  rec = send_recv_client_hello(port:port, cipherspec:cipherspec);

  # If the server resets the connection, we consider the mitigation to be
  # applied. It's not technically following the spec (supposed to send an
  # alert), but functionally it's the same.
  # It appears Citrix Netscaler devices do this.
  if (connection_reset == TRUE && isnull(rec))
    return TRUE;

  rec = ssl_parse(blob:rec);
  if (isnull(rec))
    return "no-record";

  if (rec["content_type"] == SSL3_CONTENT_TYPE_ALERT &&
      rec["level"]        == SSL3_ALERT_TYPE_FATAL &&
      rec["description"]  == SSL3_ALERT_TYPE_INAPPROPRIATE_FALLBACK)
  {
    return TRUE;
  }

  # Server responded with something that's not an INAPPROPRIATE_FALLBACK alert.
  # Probably a ServerHello. If not, something is wrong so bail.
  if (rec["content_type"]   == SSL3_CONTENT_TYPE_HANDSHAKE &&
      rec["handshake_type"] == SSL3_HANDSHAKE_TYPE_SERVER_HELLO)
  {
    return FALSE;
  }

  kb_key = "ssl_poodle_fallback_scsv_test_returned";
  if (rec["content_type"] == SSL3_CONTENT_TYPE_HANDSHAKE)
    set_kb_item(name:kb_key, value:"handshake:" + rec["handshake_type"]);
  else if (rec["content_type"] == SSL3_CONTENT_TYPE_ALERT)
    set_kb_item(name:kb_key, value:"alert:" + rec["level"] + ":" + rec["description"]);
  else
    set_kb_item(name:kb_key, value:"content_type:" + rec["content_type"]);

  return "error";
}

port = get_ssl_ports(fork:TRUE);
if (isnull(port)) exit(0, "This host has no SSL/TLS services.");
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

# Check if SSLv3 and if some form of TLS is supported
versions = make_list(get_kb_list_or_exit("SSL/Transport/" + port));
ssl3_supported = FALSE;
tls_supported = FALSE;
foreach version (versions)
{
  if (version == ENCAPS_SSLv3)
    ssl3_supported = TRUE;

  if (version >= ENCAPS_TLSv1)
    tls_supported = TRUE;
}
if (!ssl3_supported)
  exit(0, "The service on port " + port + " does not support SSLv3.");

cbc_supported = FALSE;
cipherspec = "";
foreach cipher_name (get_kb_list_or_exit("SSL/Ciphers/" + port))
{
  if (cipher_name !~ "^TLS1[12]?_")
    continue;

  if ("_CBC_" >!< cipher_name)
    continue;

  cbc_supported = TRUE;
  cipherspec += ciphers[cipher_name];
}

if (!cbc_supported)
  exit(0, "The service on port " + port + " supports SSLv3 but not any CBC cipher suites.");

# If the server supports only SSLv3 (nothing newer, like TLSv1.1) then
# there is no way to detect the TLS_FALLBACK_SCSV in action.
fallback_scsv_supported = FALSE;
if (tls_supported)
  fallback_scsv_supported = check_fallback_scsv(port:port, cipherspec:cipherspec);

if (fallback_scsv_supported == TRUE)
  exit(0, "The service on port " + port + " supports SSLv3 with CBC ciphers, but the Fallback SCSV mechanism is enabled.");

if (fallback_scsv_supported == "no-record")
  exit(0, "The service on port " + port + " supports SSLv3 with CBC ciphers, and the server did not reply while determining Fallback SCSV support.");

if (fallback_scsv_supported == "error")
  exit(0, "The service on port " + port + " supports SSLv3 with CBC ciphers, and support for Fallback SCSV could not be determined.");

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n' + 'Nessus determined that the remote server supports SSLv3 with at least one CBC ' +
    '\n' + 'cipher suite, indicating that this server is vulnerable.\n';

  if (!tls_supported)
  {
    report +=
      '\n' + 'It appears that TLSv1 or newer is not supported on the server. Mitigating this ' +
      '\n' + 'vulnerability requires SSLv3 to be disabled and TLSv1 or newer to be enabled.';
  }
  else
  {
    # We only get here if TLS is supported *and* Fallback SCSV is not enabled.
    report +=
      '\n' + 'It appears that TLSv1 or newer is supported on the server. However, the ' +
      '\n' + 'Fallback SCSV mechanism is not supported, allowing connections to be "rolled ' +
      '\n' + 'back" to SSLv3.';
  }

  report += '\n';
}
set_kb_item(name:"SSL/vulnerable_to_poodle/"+port, value:TRUE);
security_warning(port:port, extra:report);
