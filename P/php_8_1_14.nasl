#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169631);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/16");

  script_cve_id("CVE-2022-31631");
  script_xref(name:"IAVA", value:"2023-A-0016-S");

  script_name(english:"PHP 8.1.x < 8.1.14");

  script_set_attribute(attribute:"synopsis", value:
"The version PHP running on the remote web server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of PHP installed on the remote host is prior to 8.1.14. It is, therefore, affected by a vulnerability as
referenced in the Version 8.1.14 advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://bugs.php.net/81740");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-8.php#8.1.14");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 8.1.14 or later.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP", "installed_sw/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:80, php:TRUE);
var app_info = vcf::get_app_info(app:'PHP', port:port, webapp:TRUE);

var backported = get_kb_item('www/php/' + port + '/' + app_info.version + '/backported');
if ((report_paranoia < 2) && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, 'PHP ' + app_info.version + ' install');

var constraints = [
  { 'min_version' : '8.1.0alpha1', 'fixed_version' : '8.1.14' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
