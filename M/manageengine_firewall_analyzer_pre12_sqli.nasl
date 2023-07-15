#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(90446);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/29");

  script_xref(name:"EDB-ID", value:"39477");

  script_name(english:"ManageEngine Firewall Analyzer < 12.0 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of ManageEngine Firewall Analyzer running on the remote
web server is prior to 12.0. It is, therefore, affected by multiple
vulnerabilities :

  - A SQL injection vulnerability exists in the runQuery.do
    script due to improper sanitization of user-supplied
    input to the 'RunQuerycommand' parameter. An
    authenticated, remote attacker can exploit this to
    inject or manipulate SQL queries in the back-end
    database, resulting the manipulation or disclosure of
    arbitrary data.

  - Multiple cross-site scripting (XSS) vulnerabilities
    exist due to improper validation of user-supplied input.
    A remote attacker can exploit these vulnerabilities to
    execute arbitrary script code in a user's browser
    session.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://packetstormsecurity.com/files/135884/ManageEngine-Firewall-Analyzer-8.5-SQL-Injection.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15629b73");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine Firewall Analyzer version 12.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score from an in depth analysis done by Tenable");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:zohocorp:manageengine_firewall_analyzer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("manageengine_firewall_analyzer_detect.nbin");
  script_require_keys("installed_sw/ManageEngine Firewall Analyzer");
  script_require_ports("Services/www", 8500);

  exit(0);
}

include('http.inc');
include('vcf.inc');
include('vcf_extras_zoho.inc');

var app = 'ManageEngine Firewall Analyzer';
var port = get_http_port(default:8500);

var app_info = vcf::zoho::fix_parse::get_app_info(app:app, port:port, webapp:TRUE);

# Versions <= 12.0, use versions like 8.5, 12.0, etc. Otherwise, use build number.
var constraints = [
  {'min_version' : '4.0', 'max_version' : '8.5', 'fixed_display': '12.0'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE, 'sqli':TRUE}
);
