#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108803);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2008-2247", "CVE-2008-2248");
  script_bugtraq_id(30078, 30130);
  script_xref(name:"MSFT", value:"MS08-039");
  script_xref(name:"MSKB", value:"950159");
  script_xref(name:"IAVT", value:"2008-T-0033-S");

  script_name(english:"MS08-039: Outlook Web Access for Exchange Server Privilege Escalation (Uncredentialed)");
  script_summary(english:"Determines the version of Exchange");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to cross-site scripting issues.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Outlook Web Access (OWA) for
Exchange Server that is vulnerable to multiple cross-site scripting
issues in the HTML parser and Data validation code.

These vulnerabilities may allow an attacker to elevate his privileges
by convincing a user to open a malformed email.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2008/ms08-039");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for OWA 2003 and 2007.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2022 Tenable Network Security, Inc.");

  script_require_keys("installed_sw/Outlook Web Access");
  script_dependencies("owa-version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("vcf.inc");

get_install_count(app_name:"Outlook Web Access", exit_if_zero:TRUE);
port = get_http_port(default:80);
app_info = vcf::get_app_info(app:"Outlook Web Access", port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  {"min_version" : "6.5.0", "fixed_version":"6.5.7653.38"},
  {"min_version" : "8.0.0", "fixed_version":"8.0.813.0"},
  {"min_version" : "8.1.0", "fixed_version":"8.1.291.2"}
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});
