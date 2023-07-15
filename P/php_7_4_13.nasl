#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(143449);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_xref(name:"IAVA", value:"2020-A-0548-S");

  script_name(english:"PHP 7.3.x < 7.3.25 / 7.4.x < 7.4.13 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of PHP installed on the remote host is 7.3.x prior to 7.3.25 or 7.4.x prior to 7.4.13. It is, therefore,
affected by multiple vulnerabilities as specified by the changelogs of the respective fixed releases.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version");
  script_set_attribute(attribute:"see_also", value:"https://www.php.net/ChangeLog-7.php#7.3.25");
  script_set_attribute(attribute:"see_also", value:"https://www.php.net/ChangeLog-7.php#7.4.13");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.3.25, 7.4.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

constraints = [
  {'min_version':'7.3.0', 'fixed_version':'7.3.25'},
  {'min_version':'7.4.0', 'fixed_version':'7.4.13'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
