#TRUSTED 33480998d0e3b654852298f3db51624ea16bcc0d646fe14dc067374047cc85cba93233b71bbf775eee41e5c758edeb69f6cbbcd6c36b7cd3bba0b209829731e0862aacdb7cc13479697f14a00f4404b30e0111f6cd2d7e57c0de8bb3009f5c74e17fc8ac6ca0a914f5cfebc2e9223c706f3730874b0e2d5eb69c91132d581fa676fdd91fd6b866e9f24e2fe4f48e498a82b4ccb216cf709f132735643081ed11496cea220d26db0d0afd0daf1f44a3e8271ecc5e967aeb2069359ebaf7186ce6aef1e0e0a6f3fe15b73fe71016e49a55959586072830102eef35194cb4cd8d7dbda4401f2cd2c5dd20ba89a51248225d83ca0b065f93ca310376fb6a09725e31124610dc938e32f3b29a17f949c3dd2ab6c31f3d22f707cc40d0f6bcdc555bd089547e7cc670e57616a5b7c5b87a073a1896099aef894a4f0f4f1564df18dbdd115774d030c4f7a33e290327f541366cc8430473d5ea0e9897e76c3c41cb304f9e2e36f31a6a13a61195eab8c1ea37a6e8215389c9f92f49beb0b799686bebf87ac92b2362bed3d8e3c0bbbeba7a872f529e040f6820a8b065f7295eea82c51e1efbf129ca1a47363497a82d30cffc94b99cdc9ae72ea77210f95289865ae9757cbf0e4d5f0faba18d901e3f5db316eb35a56c561a72eac98da77511fc7238dd59070f9cb3e3745533aedb3f8208a813b7e0a1b6f2bbbf9be6c8ccb2445c8f30
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62574);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/12");

  script_cve_id("CVE-2012-0726");
  script_bugtraq_id(53043);

  script_name(english:"IBM Tivoli Directory Server TLS NULL Cipher (uncredentialed check)");
  script_summary(english:"Checks response from server");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote IBM Tivoli Directory Server contains an information
disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The IBM Tivoli Directory Server hosted on the remote host supports TLS
NULL-MD5 or NULL_SHA ciphers.  This allows remote, unauthenticated
attackers to trigger unencrypted communication via the TLS handshake
protocol.

Note that this version of Directory Server likely has other
vulnerabilities (i.e., CVE-2012-0743), but Nessus has not checked
for those issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www-01.ibm.com/support/docview.wss?uid=swg21591272"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Install the appropriate fix based on the vendor's advisory :

  - 6.1.0.47-ISS-ITDS-IF0047
  - 6.2.0.22-ISS-ITDS-IF0022
  - 6.3.0.11-ISS-ITDS-IF0011"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/17");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_directory_server");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2012-2020 Tenable Network Security, Inc.");

  script_dependencies("ssl_supported_versions.nasl", "ldap_search.nasl");
  script_require_ports("Services/ldap", 636);
  script_require_keys("SSL/Supported");


  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('byte_func.inc');
include("ftp_func.inc");
include("http.inc");
include("ldap_func.inc");
include("nntp_func.inc");
include("smtp_func.inc");
include("telnet2_func.inc");
include("x509_func.inc");


port = get_service(svc:'ldap', default:636, exit_on_fail:TRUE);

# Check vendor to make sure it's ITDS
vendor = get_kb_item_or_exit('LDAP/'+port+'/vendorName');
if ('IBM' >!< vendor)
  exit(0, 'The LDAP server listening on port '+port+' does not appear to be an IBM product.');

# Check for TLSv1 on remote port
tls10 = 0;
list = get_kb_list('SSL/Transport/'+port);
if (!isnull(list))
{
  list = make_list(list);
  foreach encap (list)
  {
    if(encap == ENCAPS_TLSv1)
    {
      tls10 = 1;
      break;
    }
  }
}

if (!tls10) exit(0, 'The LDAP server listening on port '+port+' does not appear to support TLS 1.0.');

soc = open_sock_ssl(port);
if (!soc) exit(0, 'open_sock_ssl() failed on port '+port+'.');

# Create a ClientHello record with NULL_MD5 and NULL_SHA ciphers
cipher  = ciphers['TLS1_CK_RSA_WITH_NULL_SHA'];
cipher += ciphers['TLS1_CK_RSA_WITH_NULL_MD5'];
helo = client_hello(
  version    : raw_string(0x03, 0x01), # TLSv1
  cipherspec : cipher,
  cspeclen   : mkword(strlen(cipher)),
  v2hello    : FALSE
);

# Send the ClientHello record
send(socket:soc, data:helo);
rec = recv_ssl(socket:soc);
close(soc);

if(isnull(rec)) audit(AUDIT_RESP_NOT, port);

# Check if a ServerHello is returned
msg = ssl_find(
  blob:rec,
  'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
  'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO
);


# Patched server (6.3.0.11) returns a 'Handshake Failure' fatal alert.
# So the patched server didn't accept TLS1_CK_RSA_WITH_NULL_SHA, and it's not vulnerable.
if(isnull(msg))
  exit(0, 'The LDAP server listening on port '+port+' did not return a ServerHello message, and thus is probably not affected.');

# Vulnerable server (6.3.0.10) returns a ServerHello.
# Make sure the server selected TLS1_CK_RSA_WITH_NULL_SHA or TLS1_CK_RSA_WITH_NULL_MD5
chosen = mkword(msg['cipher_spec']);
if(chosen == ciphers['TLS1_CK_RSA_WITH_NULL_SHA'] || chosen == ciphers['TLS1_CK_RSA_WITH_NULL_MD5'])
  security_warning(port);
else audit(AUDIT_RESP_BAD, port);
