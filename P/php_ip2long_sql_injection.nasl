#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(17715);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2006-4023");

  script_name(english:"PHP ip2long Function String Validation Weakness");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that does not properly
validate user strings.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the 'ip2long()' function in the version of
PHP installed on the remote host may incorrectly validate an arbitrary
string and return a valid network IP address.");
  # https://web.archive.org/web/20141122094639/http://retrogod.altervista.org/php_ip2long.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f88768a");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/441529/100/100/threaded");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.1.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2006-4023");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2022 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP", "Settings/PCI_DSS", "installed_sw/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http.inc');
include('vcf.inc');

# Only PCI considers this an issue.
if (!get_kb_item('Settings/PCI_DSS')) audit(AUDIT_PCI);

port = get_http_port(default:80, php:TRUE);
app_info = vcf::get_app_info(app:'PHP', port:port, webapp:TRUE);

backported = get_kb_item('www/php/' + port + '/' + app_info.version + '/backported');

if ((report_paranoia < 2) && backported) audit(AUDIT_BACKPORT_SERVICE, port, 'PHP ' + app_info.version + ' install');

constraints = [ {'min_version':'4.0.0alpha1', 'fixed_version':'5.1.5'} ];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
