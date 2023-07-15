#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105156);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-16664");

  script_name(english:"OTRS Authenticated Remote Code Execution (OSA-2017-07)");
  script_summary(english:"Checks the product version.");

  script_set_attribute(attribute:"synopsis", value:
"A service management application running on the remote host is affected by
a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of OTRS running on the remote host is 3.3.x prior to 
3.3.20, 4.0.x prior to 4.0.26, or 5.0.x prior to 5.0.24. It is, 
therefore, affected by a remote code execution vulnerability.");
  # https://www.otrs.com/security-advisory-2017-07-security-update-otrs-framework/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?48f3eb3b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OTRS version 3.3.20 / 4.0.26 / 5.0.24 later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-16664");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:otrs:otrs");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (app.version !~ "^3\.3" && app.version !~ "^[45]\.0") 
  audit(AUDIT_UNKNOWN_WEB_APP_VER, app.app, build_url(port:app.port, qs:app.path));

constraints = 
[
  {"min_version" : "3.3.0", "fixed_version" : "3.3.20"},
  {"min_version" : "4.0.0", "fixed_version" : "4.0.26"},
  {"min_version" : "5.0.0", "fixed_version" : "5.0.24"}
];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_WARNING, strict:FALSE);
