#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129557);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"PHP 7.3.x < 7.3.10 Heap-Based Buffer Overflow Vulnerability.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a head-based buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web server is 7.3.x prior to 7.3.10. It is, 
therefore, affected by a heap-based buffer overflow vulnerability in its mb_eregi component due to insufficient 
validation of user input. An unauthenticated, remote attacker can exploit this, by sending a specially crafted request,
to cause a denial of service condition or the execution of arbitrary code");
  script_set_attribute(attribute:"see_also", value:"https://www.php.net/ChangeLog-7.php#PHP_7_3");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=78559");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.3.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/04");

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
app_info = vcf::get_app_info(app:'PHP', port:port, webapp:TRUE);

backported = get_kb_item('www/php/' + port + '/' + app_info.version + '/backported');

if ((report_paranoia < 2) && backported) audit(AUDIT_BACKPORT_SERVICE, port, 'PHP ' + app_info.version + ' install');

constraints = [{'min_version':'7.3.0alpha1', 'fixed_version':'7.3.10'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
