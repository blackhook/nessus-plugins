#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133400);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-7059", "CVE-2020-7060");

  script_name(english:"PHP 7.2.x < 7.2.27 / PHP 7.3.x < 7.3.14 / 7.4.x < 7.4.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is either 7.2.x prior to 7.2.27, 7.3.x prior to 7.3.14, or 
7.4.x prior to 7.4.2. It is, therefore, affected by multiple vulnerabilities:

  - An buffer overflow on the mbfl_filt_conv_big5_wchar` function. An 
    unauthenticated, remote attacker can exploit this to leading to the 
    disclosure of information within memory locations and possibly allow 
    for the execution of malicious code. (CVE-2020-7060)

  - An out-of-bounds READ error exists in the php_strip_tags_ex due to
    an input validation error. An unauthenticated, remote attacker 
    can exploit this, leading to the disclosure of information within 
    some memory locations. (CVE-2020-7059)");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-7.php#7.2.27");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-7.php#7.3.14");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-7.php#7.4.2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.2.27, 7.3.14, 7.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7060");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP", "installed_sw/PHP", "Settings/ParanoidReport");
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

constraints = [
    {'min_version':'7.2.0alpha1', 'fixed_version':'7.2.27'},
    {'min_version':'7.3.0alpha1', 'fixed_version':'7.3.14'},
    {'min_version':'7.4.0alpha1', 'fixed_version':'7.4.2'}
    ];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
