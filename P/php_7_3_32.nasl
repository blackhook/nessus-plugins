#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154663);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/11");

  script_cve_id("CVE-2021-21703");
  script_xref(name:"IAVA", value:"2021-A-0503-S");

  script_name(english:"PHP 7.3.x < 7.3.32");

  script_set_attribute(attribute:"synopsis", value:
"The version PHP running on the remote web server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of PHP installed on the remote host is prior to 7.3.32. It is, therefore, affected by a vulnerability as
referenced in the Version 7.3.32 advisory.

  - In PHP versions 7.3.x up to and including 7.3.31, 7.4.x below 7.4.25 and 8.0.x below 8.0.12, when running
    PHP FPM SAPI with main FPM daemon process running as root and child worker processes running as lower-
    privileged users, it is possible for the child processes to access memory shared with the main process and
    write to it, modifying it in a way that would cause the root process to conduct invalid memory reads and
    writes, which can be used to escalate privileges from local unprivileged user to the root user.
    (CVE-2021-21703)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://bugs.php.net/81026");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-7.php#7.3.32");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.3.32 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21703");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '7.3.0alpha1', 'fixed_version' : '7.3.32' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
