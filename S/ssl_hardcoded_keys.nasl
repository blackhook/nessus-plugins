#TRUSTED 9db9380d8dfbe1e9a3a8a1b34174f18867c79449d37a3dc5a29788a0eb45dc3046b310f51585dfc9e5b46d7af4dd8f678b31d2c1e95794257e01480bad51799de32afe22cba9b67c3548cf47e0ecdff982b73d9977d09e4936f24f8818b493e055fb45a963c98fb5ab4302f0f7026a52d3d8c4185b3d9c94e61ab1be2d0facc292f49e73628ffb4fd70b2ad16033c310789297e56091e258fa9ee01a50471dbfc938422dcc23ec818335dba77111bd3fae40c9010bdad59ccaafcb4d53ddd31518948727a82e2ed37f651385cde9716824d6312753431377d45ecf229ed47ca3718bfb0e343cd0f0de79369386bc8280b409d434532b32b924e36f75db979457d337ea4c42a0ec7609506802f1b1a2beef6b2539478e964e228b910c32003caf902cc43b2ddafaef797221dbce8f2bb51c7fb86a136ed5ec025331d84c5615673d7a41b500c277420a099e796219d49d8186749096f61bd0158c27f68e38b0658fe0357d8a62905172ddb4cf2663b6a60bfb97b86ce4a182ff90dc536e3b372144204ff606bd5dad9935d2b98badec94c6b1780f5bc88a51edcf7b2b36e4d4f982373f168983f44e5609afbce9236f248c258f5c03337640340dab4265add896dfc8e20faa5822c8d62c44bdf9e18c256022e7dfad4551c9b17ed7b57106f655e26c5a3defd7a5ea9d002d687abfb518208fa7c29c1c9543d695bf89b4d4769d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121008);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/12");

  script_cve_id(
    "CVE-2015-6358",
    "CVE-2015-7255",
    "CVE-2015-7256",
    "CVE-2015-7276",
    "CVE-2015-8251"
  );

  script_name(english:"SSL / TLS Certificate Known Hard Coded Private Keys");
  script_summary(english:"Determines if publicly known hard coded SSL / TLS private keys are in use.");

  script_set_attribute(attribute:"synopsis", value:
"Known SSL / TLS private keys in use.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a service that is using a publicly known SSL / TLS private key.
An attacker may use this key to decrypt intercepted traffic between users and the device.
A remote attacker can also perform a man-in-the-middle attack in order to gain access to the
system or modify data in transit.");
  # https://sec-consult.com/en/blog/2015/11/house-of-keys-industry-wide-https/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?48f09948");
  script_set_attribute(attribute:"see_also", value:"https://github.com/sec-consult/houseofkeys");
  script_set_attribute(attribute:"see_also", value:"https://www.kb.cert.org/vuls/id/566724/");
  script_set_attribute(attribute:"solution", value:
"Where possible, change the X.509 certificates so that they are unique to the device
or contact vendor for guidance.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7255");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssl_supported_versions.nasl");
  script_require_keys("SSL/Supported");

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("ldap_func.inc");
include("ftp_func.inc");
include("misc_func.inc");
include("nntp_func.inc");
include("smtp_func.inc");
include("telnet_func.inc");
include("telnet2_func.inc");
include("x509_func.inc");
include("ssl_funcs.inc");
include("ssl_hardcoded_fingerprints.inc");

get_kb_item_or_exit("SSL/Supported");
port = get_ssl_ports(fork:TRUE);
if (isnull(port)) exit(1, "The host does not appear to have any SSL-based services.");

soc = open_sock_ssl(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

cert = get_server_cert(socket:soc, port:port, encoding:"der");

if (isnull(cert))
  exit(1, "Failed to read server cert from port " + port + ".");

fingerprint = fingerprint_cert(cert:cert, type:'sha1');
if(empty_or_null(fingerprint)) audit(AUDIT_FN_FAIL, "fingerprint_cert");
fingerprint = ereg_replace(pattern:':', replace:'', string:fingerprint);
if(empty_or_null(fingerprint)) audit(AUDIT_FN_FAIL, "ereg_replace");

res = check_ssl_fingerprint(fingerprint:fingerprint, type:'sha1');

if (!isnull(res))
{
  report = '\n- HTTPS certificate fingerprint : ' + toupper(fingerprint) +
           '\n  HTTPS fingerprint type        : SHA1' +
           '\n  Reference                     : ' + res + '\n';
  security_report_v4(port:port,
                     severity:SECURITY_WARNING,
                     extra:report);
  exit(0);
}

audit(AUDIT_HOST_NOT, 'affected');
