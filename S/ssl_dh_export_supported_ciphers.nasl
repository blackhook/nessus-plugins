#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(83738);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2015-4000");
  script_bugtraq_id(74733);
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"SSL/TLS EXPORT_DHE <= 512-bit Export Cipher Suites Supported (Logjam)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host supports a set of weak ciphers.");
  script_set_attribute(attribute:"description", value:
"The remote host supports EXPORT_DHE cipher suites with keys less than
or equal to 512 bits. Through cryptanalysis, a third party can find
the shared secret in a short amount of time.

A man-in-the middle attacker may be able to downgrade the session to
use EXPORT_DHE cipher suites. Thus, it is recommended to remove
support for weak cipher suites.");
  script_set_attribute(attribute:"see_also", value:"https://weakdh.org/");
  script_set_attribute(attribute:"solution", value:
"Reconfigure the service to remove support for EXPORT_DHE cipher
suites.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"An in depth analysis by Tenable researchers revealed the Access Complexity to be high.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

c_report = cipher_report(supported_ciphers, name:"_CK_DHE?_.*_EXPORT_");

if (isnull(c_report))
  exit(0, "No EXPORT_DHE cipher suites are supported on " + pp_info["l4_proto"] + " port " + port + ".");

# Report our findings.
report =
  '\nEXPORT_DHE cipher suites supported by the remote server :' +
  '\n' + c_report;

security_report_v4(port:port, proto:pp_info["l4_proto"], extra:report, severity:SECURITY_NOTE);

