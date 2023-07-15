#TRUSTED 9c525e12bd1f76c6ccef309bffcc446d69af3a6aab67d1a8af22a53338b0713a8010674cb399aa4e744b84b41c0a9fd1269374b65b81b5be33d11abb25d5250409519230142b8cf069f3483b6ed7d5fe794da40e6a7a48b8fd97359dd932a9b9a5b3a7fdf0aa333c69051f15e0b43fe7b2b702ce3e0e2df69af468c97a912b67ef796ff476fbda33ae0bf89e749077d6470c934e5690abed8b6570a69630259e786dc015815e3189a96888c71cdbdde74b53ee9bc8251c1aeba045ffa4d6b24922cb68c25d6b6ac757636bba4d117df73c839c8aa022f35b58c815d46c4698dd14d052e7eaaf2bceb8c7c64eef1aa9ecc7c25295d2e3806a08af0da3d62aca7f6bb9717bbe9e7d2e0fcc8b3ad99e867ad297d77a705ee0538fe7288c35c4cd3f52b849f0a84ca851702ce7512a8c7fde8714df8eb2946f22c379fec6eed1ab43a3ee24ddfb9f8db3b23bfd4708c7a6e385b62d24f09aaba806ab5ede58dfc67f3286000ba9342111106711385312076a17cf8728ed66041477674ea0a595336d3ec7212f605fe30167f7530f3cd579bbb1f2a1272e55bf304e97e6fce0f5b52bb3dae6eed3acafaf78fcfaa1dc71a4c4b3dd760275582b8d6aa2173d4df6b18aecac9e8b6f719c4258e10f90dd0e20c8b81c165b78f52ddbfae68dc59f38ac9c72d6ba48bb47fad297b220d531a8f2b58ebf334f036bade434359da8ed9b851c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74326);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/12");

  script_cve_id(
    "CVE-2010-5298",
    "CVE-2014-0076",
    "CVE-2014-0195",
    "CVE-2014-0198",
    "CVE-2014-0221",
    "CVE-2014-0224",
    "CVE-2014-3470"
  );
  script_bugtraq_id(
    66363,
    66801,
    67193,
    67898,
    67899,
    67900,
    67901
  );
  script_xref(name:"CERT", value:"978508");

  script_name(english:"OpenSSL 'ChangeCipherSpec' MiTM Potential Vulnerability");
  script_summary(english:"Checks if the remote host incorrectly accepts a 'ChangeCipherSpec' message.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is potentially affected by a vulnerability that could
allow sensitive data to be decrypted.");
  script_set_attribute(attribute:"description", value:
"The OpenSSL service on the remote host is potentially vulnerable to a
man-in-the-middle (MiTM) attack, based on its response to two
consecutive 'ChangeCipherSpec' messages during the incorrect phase of
an SSL/TLS handshake.

This flaw could allow a MiTM attacker to decrypt or forge SSL messages
by telling the service to begin encrypted communications before key
material has been exchanged, which causes predictable keys to be used
to secure future traffic.

OpenSSL 1.0.1 is known to be exploitable. OpenSSL 0.9.8 and 1.0.0 are
not known to be vulnerable; however, the OpenSSL team has advised that
users of these older versions upgrade as a precaution. This plugin
detects and reports all versions of OpenSSL that are potentially
exploitable.

Note that Nessus has only tested for an SSL/TLS MiTM vulnerability
(CVE-2014-0224). However, Nessus has inferred that the OpenSSL service
on the remote host is also affected by six additional vulnerabilities
that were disclosed in OpenSSL's June 5th, 2014 security advisory :

  - An error exists in the 'ssl3_read_bytes' function
    that permits data to be injected into other sessions
    or allows denial of service attacks. Note that this
    issue is exploitable only if SSL_MODE_RELEASE_BUFFERS
    is enabled. (CVE-2010-5298)

  - An error exists related to the implementation of the
    Elliptic Curve Digital Signature Algorithm (ECDSA) that
    allows nonce disclosure via the 'FLUSH+RELOAD' cache
    side-channel attack. (CVE-2014-0076)

  - A buffer overflow error exists related to invalid DTLS
    fragment handling that permits the execution of
    arbitrary code or allows denial of service attacks.
    Note that this issue only affects OpenSSL when used
    as a DTLS client or server. (CVE-2014-0195)

  - An error exists in the 'do_ssl3_write' function that
    permits a NULL pointer to be dereferenced, which could
    allow denial of service attacks. Note that this issue
    is exploitable only if SSL_MODE_RELEASE_BUFFERS is
    enabled. (CVE-2014-0198)

  - An error exists related to DTLS handshake handling that
    could allow denial of service attacks. Note that this
    issue only affects OpenSSL when used as a DTLS client.
    (CVE-2014-0221)

  - An error exists in the 'dtls1_get_message_fragment'
    function related to anonymous ECDH cipher suites. This
    could allow denial of service attacks. Note that this
    issue only affects OpenSSL TLS clients. (CVE-2014-3470)

OpenSSL did not release individual patches for these vulnerabilities,
instead they were all patched under a single version release. Note
that the service will remain vulnerable after patching until the
service or host is restarted.");
  # http://ccsinjection.lepidum.co.jp/blog/2014-06-05/CCS-Injection-en/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5709faa");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/06/05/earlyccs.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"solution", value:
"OpenSSL 0.9.8 SSL/TLS users (client and/or server) should upgrade to
0.9.8za. OpenSSL 1.0.0 SSL/TLS users (client and/or server) should
upgrade to 1.0.0m. OpenSSL 1.0.1 SSL/TLS users (client and/or server)
should upgrade to 1.0.1h.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0224");
  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2014-2020 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("ssl_supported_versions.nasl", "openssl_ccs_1_0_1.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports(443, "SSL/Supported");
  exit(0);
}

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
include("audit.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if ( get_kb_item("SSL/Supported") )
{
 port = get_ssl_ports(fork:TRUE);
 if (isnull(port))
   exit(1, "The host does not appear to have any SSL-based services.");

 ssl3 = tls10 = tls11 = tls12 = 0;

 list = get_kb_list('SSL/Transport/'+port);
 if(! isnull(list))
 {
  list = make_list(list);
  foreach encap (list)
  {
    if      (encap == ENCAPS_SSLv3)         ssl3 = 1;
    else if (encap == ENCAPS_TLSv1)         tls10 = 1;
    else if (encap == COMPAT_ENCAPS_TLSv11) tls11 = 1;
    else if (encap == COMPAT_ENCAPS_TLSv12) tls12 = 1;
  }
 }

 if(! (ssl3 || tls10 || tls11 || tls12))
   exit(0, 'The SSL-based service listening on port '+port+' does not appear to support SSLv3 or above.');

 if (tls12)       version = TLS_12;
 else if (tls11)  version = TLS_11;
 else if (tls10)  version = TLS_10;
 else if (ssl3)   version = SSL_V3;
}
else
{
 if ( ! get_port_state(443) ) exit(1, "No SSL port discovered and port 443 is closed.");
 port = 443;
 version = TLS_10;
}

if (get_kb_item("SSL/earlyccs-1.0.1/" + port) == "true")
  exit(0, "Port " + port + " has already been shown to be vulnerable to CVE-2014-0224.");

# Open port
soc = open_sock_ssl(port);
if ( ! soc ) audit(AUDIT_SSL_FAIL, "SSL", port);

ver  = mkword(version);

cipherspec = NULL;
foreach cipher (sort(keys(ciphers)))
{
  if(strlen(ciphers[cipher]) == 2)
  {
    cipherspec +=  ciphers[cipher];
  }
}
cspeclen = mkword(strlen(cipherspec));

exts = tls_ext_ec() + tls_ext_ec_pt_fmt();
exts_len  = mkword(strlen(exts));

chello = client_hello(v2hello:FALSE, version:ver,
                      cipherspec : cipherspec,
                      cspeclen   : cspeclen,
                      extensions:exts,extensionslen:exts_len
                      );

send(socket:soc, data: chello);

# Read one record at a time. Expect to see at a minimum:
# ServerHello, Certificate, and ServerHelloDone.
hello_done = FALSE;
while (!hello_done)
{
  # Receive a record from the server.
  data = recv_ssl(socket:soc);
  if (isnull(data))
  {
    close(soc);
    exit(1, 'Service on TCP port ' + port + ' did not respond to ClientHello.');
  }

  # Server Hello Done.
  rec = ssl_find(
    blob:data,
    'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
    'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO_DONE
  );

  if (!isnull(rec))
  {
    hello_done = TRUE;

    # Make sure we use an SSL version supported by the server
    if(rec['version'] != version && rec['version'] >= 0x0300 && rec['version'] <= 0x0303)
      version = rec['version'];

    break;
  }
}

if(! hello_done)
  exit(1, 'ServerHelloDone not received from server listening on port ' + port+'.');

# The data in a ChangeCipherSpec message is a single byte of value '1'
if (version == SSL_V3)
  ccs = ssl_mk_record(version:version, type:SSL3_CONTENT_TYPE_CHANGECIPHERSPEC, data:mkbyte(0x01));
else
  ccs = tls_mk_record(version:version, type:SSL3_CONTENT_TYPE_CHANGECIPHERSPEC, data:mkbyte(0x01));

send(socket:soc, data:ccs);
rec = recv_ssl(socket:soc, partial:TRUE);

# Microsoft SSL services will close the connection with a TCP RST
if (isnull(rec) && socket_get_error(soc) == ECONNRESET)
  exit(0, 'The service listening on TCP port ' + port + ' closed the connection when sent an early ChangeCipherSpec message, which suggests it is not vulnerable.');

# If we got something back, it might be an alert or it might be garbage
if (!isnull(rec))
{
  parsed_rec = ssl_find(
    blob:rec,
    'content_type', SSL3_CONTENT_TYPE_ALERT,
    'description',  SSL3_ALERT_TYPE_UNEXPECTED_MESSAGE,
    'level',        SSL3_ALERT_TYPE_FATAL
  );

  close(soc);

  if (!isnull(parsed_rec))
    exit(0, 'The service listening on TCP port ' + port + ' returned an SSL alert when sent an early ChangeCipherSpec message, indicating it is not vulnerable.');
  else
    exit(1, 'The service listening on TCP port ' + port + ' responded to an early ChangeCipherSpec message, but not with a fatal SSL alert message.');
}

# We did not receive anything back, but the connection was not forcibly closed by the server.
# Probably vulnerable, but we want to confirm it's not a network latency issue or something.
# We try sending a second ChangeCipherSpec message - if the service processed our first one, it will have
# set up (bad) keys and will now be expecting encrypted messages. This second ChangeCipherSpec message will
# not be encrypted, so we will get an SSL3_ALERT_TYPE_DECRYPTION_FAILED alert from the server.

send(socket:soc, data:ccs);
rec = recv_ssl(socket:soc, partial:TRUE);

close(soc);

report = NULL;

# If we didn't get a reply to a second CCS, probably vulnerable, but could be caused by network outage.
if (isnull(rec))
{
  if (report_paranoia < 2)
    exit(1, "The service listening on TCP port " + port + ' did not respond to two consecutive ChangeCipherSpec messages.');

  report =
    '\nThe remote service accepted two consecutive ChangeCipherSpec messages at an incorrect point in the ' +
    '\nhandshake, without closing the connection or sending an SSL alert. This behavior indicates that the ' +
    '\nservice is vulnerable; however, this could also be the result of network interference.' +
    '\n';
}
# We got a reply to a second CCS, check if it's an SSL alert.
else
{
  # Is it a "decryption failed" alert?
  parsed_rec = ssl_find(
    blob:rec,
    'content_type', SSL3_CONTENT_TYPE_ALERT,
    'description',  SSL3_ALERT_TYPE_DECRYPTION_FAILED,
    'level',        SSL3_ALERT_TYPE_FATAL
  );

  # Is it a "bad MAC" alert?
  if (isnull(parsed_rec))
  {
    parsed_rec = ssl_find(
      blob:rec,
      'content_type', SSL3_CONTENT_TYPE_ALERT,
      'description',  SSL3_ALERT_TYPE_BAD_RECORD_MAC,
      'level',        SSL3_ALERT_TYPE_FATAL
    );
  }

  # If it's neither a "bad MAC" or "decryption failed" alert...
  if (isnull(parsed_rec))
    exit(1, 'The service listening on TCP port ' + port + ' responded to two consecutive ChangeCipherSpec messages, but not with a fatal SSL alert message.');

  report =
    '\nThe remote service accepted an SSL ChangeCipherSpec message at an incorrect point in the handshake ' +
    '\nleading to weak keys being used, and then attempted to decrypt an SSL record using those weak keys.' +
    '\nThis plugin detects unpatched OpenSSL 1.0.1, 1.0.0, and 0.9.8 services. Only 1.0.1 has been shown to ' +
    '\nbe exploitable; however, OpenSSL 1.0.0 and 0.9.8 have received similar patches and users of these ' +
    '\nversions have been advised to upgrade as a precaution.' +
    '\n';
}

if (report_verbosity == 0)
  report = NULL;

security_warning(port:port, extra: report);
