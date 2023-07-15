#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122156);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/02 21:54:16");

  script_cve_id("CVE-2017-16921");

  script_name(english:"OTRS Authenticated Remote Code Execution (OSA-2017-09)");
  script_summary(english:"Checks the product version.");

  script_set_attribute(attribute:"synopsis", value:
"A service management application running on the remote host is affected by
a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of OTRS running on the remote host is 4.0.x prior to 
4.0.27, 5.0.x prior to 5.0.25, or 6.0.x prior to 6.0.2. It is, 
therefore, affected by a remote code execution vulnerability due to
improper validation of user-supplied data. An authenticated, remote
attacker can manipulate form parameters and execute arbitrary shell
commands with the permissions of the OTRS or web server user.");
  # https://community.otrs.com/security-advisory-2017-09-security-update-otrs-framework/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e19d6550");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OTRS version 4.0.27 / 5.0.25 / 6.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-16921");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:otrs:otrs");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("otrs_detect.nbin");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("vcf.inc");

port = get_http_port(default:80);
app = vcf::get_app_info(app:"OTRS Web", webapp:TRUE, port:port);
if (app.version !~ "^[456]\.0")
{
  exit(0, 'The version of ' + app.app + ' listening at ' +
    build_url(port:app.port, qs:app.path) + ' is not 4.0.x, 5.0.x, or 6.0.x.');
}

constraints =
[
  {"min_version" : "4.0.0", "fixed_version" : "4.0.27"},
  {"min_version" : "5.0.0", "fixed_version" : "5.0.25"},
  {"min_version" : "6.0.0", "fixed_version" : "6.0.2"},
];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_HOLE, strict:FALSE);
