#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123753);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-11034", "CVE-2019-11035");
  script_bugtraq_id(107794);

  script_name(english:"PHP 7.1.x < 7.1.28 Multiple vulnerabilities.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by
 multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is 7.1.x prior to 7.1.28. It is, therefore, affected by
multiple vulnerabilities:

  - A heap-based buffer over-read condition exists in 
    php_ifd_get32s in exif.c.

  - A heap-based buffer overflow condition exists in 
    exif_iif_add_value in exif.c as a result of improperly
    checking input length.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-7.php#7.1.28");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.1.28 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11034");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('http.inc');
include('webapp_func.inc');

fix = '7.1.28';
minver = '7.1.0alpha1';

regexes = make_array(
  -3, 'alpha(\\d+)',
  -2, 'beta(\\d+)',
  -1, 'RC(\\d+)'
);

port = get_http_port(default:80, php:TRUE);

php = get_php_from_kb(
  port : port,
  exit_on_fail : TRUE
);

ver = php["ver"];
source = php["src"];
backported = get_kb_item('www/php/' + port + '/' + ver + '/backported');

if ((report_paranoia < 2) && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, 'PHP ' + ver + ' install');

vulnerable = ver_compare(minver:minver, ver:ver, fix:fix, regexes:regexes);
if (isnull(vulnerable)) exit(1, 'The version of PHP ' + ver + ' is not within the checked ranges.');
if (vulnerable > -1) audit(AUDIT_LISTEN_NOT_VULN, 'PHP', port, ver);

report =
'\n  Version source    : ' + source +
'\n  Installed version : ' + ver +
'\n  Fixed version     : ' + fix +
'\n';
security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
