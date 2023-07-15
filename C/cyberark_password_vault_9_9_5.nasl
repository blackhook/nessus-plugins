#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108952);
  script_version("1.10");
  script_cvs_date("Date: 2019/10/07 15:15:27");

  script_cve_id("CVE-2018-9843");
  script_bugtraq_id(105180);
  script_xref(name:"IAVB", value:"2018-B-0121");

  script_name(english:"CyberArk Password Vault Web Access .NET Object Deserialization");
  script_summary(english:"Looks for the product and version in the logon page.");

  script_set_attribute(attribute:"synopsis", value:
"An Identity Management application running on the remote host is affected by
a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of CyberArk Password Vault Web Access running on the
remote host is prior to 9.9.5, 9.10.x prior to 9.10.1, or is version
10.1. It is, therefore, vulnerable to a remote code execution
vulnerability.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.
");
  # https://www.redteam-pentesting.de/en/advisories/rt-sa-2017-014/-cyberark-password-vault-web-access-remote-code-execution
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e1d84c64");
  script_set_attribute(attribute:"solution", value:
"Upgrade to CyberArk Password Vault 9.9.5, 9.10.1, 10.2 or Later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-9843");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cyberark:password_vault");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cyberark_password_vault_detection.nbin");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("vcf.inc");
include("vcf_extras.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);
app = vcf::get_app_info(app:"CyberArk Password Vault Web Access", webapp:TRUE, port:port);

constraints = 
[
  {"min_version" : "0.0.0", "fixed_version" : "9.9.5"},
  {"min_version" : "9.10.0", "fixed_version" : "9.10.1"},
  {"min_version" : "10.1",  "fixed_version" : "10.2"}
];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_HOLE, strict:FALSE);
