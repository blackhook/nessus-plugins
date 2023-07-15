#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81606);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/03");

  script_cve_id("CVE-2015-0204");
  script_bugtraq_id(71936);
  script_xref(name:"CERT", value:"243585");

  script_name(english:"SSL/TLS EXPORT_RSA <= 512-bit Cipher Suites Supported (FREAK)");
  script_summary(english:"The remote host supports a weak set of ciphers.");

  script_set_attribute(attribute:"synopsis", value:"The remote host supports a set of weak ciphers.");
  script_set_attribute(attribute:"description", value:
"The remote host supports EXPORT_RSA cipher suites with keys less than
or equal to 512 bits. An attacker can factor a 512-bit RSA modulus in
a short amount of time.

A man-in-the middle attacker may be able to downgrade the session to
use EXPORT_RSA cipher suites (e.g. CVE-2015-0204). Thus, it is
recommended to remove support for weak cipher suites.");
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com/#freak");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20150108.txt");
  # https://github.com/openssl/openssl/commit/ce325c60c74b0fa784f5872404b722e120e5cab0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b78da2c4");
  script_set_attribute(attribute:"solution", value:
"Reconfigure the service to remove support for EXPORT_RSA cipher
suites.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0204");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssl_supported_ciphers.nasl");
  script_require_ports("SSL/Supported", "DTLS/Supported");
  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");

if(!get_kb_item("SSL/Supported") && !get_kb_item("DTLS/Supported"))
  exit(1, "Neither the 'SSL/Supported' nor the 'DTLS/Supported' flag is set.");

pp_info = get_tls_dtls_ports(fork:TRUE, dtls:TRUE, check_port:TRUE, ciphers:TRUE);
port = pp_info["port"];
if (isnull(port))
  exit(1, "The host does not appear to have any TLS or DTLS based services.");

if(pp_info["proto"] != "tls" && pp_info["proto"] != "dtls")
  exit(1, "A bad protocol was returned from get_tls_dtls_ports(). (" + pp_info["port"] + "/" + pp_info["proto"] + ")");

supported_ciphers = pp_info["ciphers"];
if (isnull(supported_ciphers))
  exit(0, "No ciphers were found for " + pp_info["l4_proto"] + " port " + port + ".");
supported_ciphers = make_list(supported_ciphers);

c_report = cipher_report(supported_ciphers, name:"_CK_RSA_EXPORT_");

if (isnull(c_report))
  exit(0, "No EXPORT_RSA cipher suites are supported on " + pp_info["l4_proto"] + " port " + port + ".");

# Report our findings.
report =
  '\nEXPORT_RSA cipher suites supported by the remote server :' +
  '\n' + c_report;

security_report_v4(port:port, proto:pp_info["l4_proto"], extra:report, severity:SECURITY_WARNING);

