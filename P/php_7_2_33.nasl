#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(139571);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-7068");
  script_xref(name:"IAVA", value:"2020-A-0373-S");

  script_name(english:"PHP 7.2.x < 7.2.33 Use-After-Free Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by a use-after-free vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of PHP running on the remote web server is 7.2.x prior to
7.2.33. It is, therefore affected by a use-after-free vulnerability in the phar_parse function due to mishandling of the
actual_alias variable. An unauthenticated, remote attacker could exploit this issue by dereferencing a freed pointer
which could lead to arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"http://bugs.php.net/79797");
  script_set_attribute(attribute:"see_also", value:"https://www.php.net/ChangeLog-7.php#7.2.33");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.2.33");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7068");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP", "installed_sw/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http.inc');
include('vcf.inc');

port = get_http_port(default:80, php:TRUE);
app_info = vcf::get_app_info(app:'PHP', port:port, webapp:TRUE);

backported = get_kb_item('www/php/' + port + '/' + app_info.version + '/backported');
if ((report_paranoia < 2) && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, 'PHP ' + app_info.version + ' install');

constraints = [{'min_version':'7.2.0alpha1', 'fixed_version':'7.2.33'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);



