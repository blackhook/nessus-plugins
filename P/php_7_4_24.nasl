#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154656);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/11");

  script_cve_id("CVE-2021-21706");
  script_xref(name:"IAVA", value:"2021-A-0503-S");

  script_name(english:"PHP 7.4.x < 7.4.24 Arbitrary File Write");

  script_set_attribute(attribute:"synopsis", value:
"The version PHP running on the remote web server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of PHP installed on the remote host is 7.4.x prior to 7.4.25. It is, therefore, affected by a
vulnerability as referenced in the version 7.4.24 advisory. In the Microsoft Windows environment, ZipArchive::extractTo
may be tricked into writing a file outside target directory when extracting a ZIP file, thus potentially causing files
to be created or overwritten, subject to OS permissions.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://bugs.php.net/81420");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-7.php#7.4.24");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.4.24 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21706");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("php_version.nasl", "os_fingerprint.nasl");
  script_require_keys("www/PHP", "installed_sw/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var os = get_kb_item_or_exit("Host/OS");
if (tolower(os) !~ 'windows')
  audit(AUDIT_OS_NOT, 'Windows');

var port = get_http_port(default:80, php:TRUE);
var app_info = vcf::get_app_info(app:'PHP', port:port, webapp:TRUE);

var backported = get_kb_item('www/php/' + port + '/' + app_info.version + '/backported');
if ((report_paranoia < 2) && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, 'PHP ' + app_info.version + ' install');

var constraints = [
  { 'min_version' : '7.4.0alpha1', 'fixed_version' : '7.4.24' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
