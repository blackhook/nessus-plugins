#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127132);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-11041", "CVE-2019-11042");

  script_name(english:"PHP 7.3.x < 7.3.8 Multiple Vulnerabilities.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web server is 7.3.x prior to 7.3.8. It is,
therefore, affected by buffer overflow vulnerabilities in exif_read_data and exif_scan_thumbnail functions.");
  script_set_attribute(attribute:"see_also", value:"https://www.php.net/ChangeLog-7.php#7.3.8");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=78222");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=78256");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.3.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11042");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP", "installed_sw/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http.inc');
include('vcf.inc');
include('audit.inc');

port = get_http_port(default:80, php:TRUE);
app = 'PHP';

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

backported = get_kb_item('www/php/' + port + '/' + app_info.version + '/backported');
if ((report_paranoia < 2) && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, 'PHP ' + app_info.version + ' install');

constraints = [{'min_version':'7.3.0alpha1', 'fixed_version':'7.3.8'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
