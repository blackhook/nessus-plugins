#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131319);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-18622");

  script_name(english:"phpMyAdmin 4.7.7 < 4.9.2 SQLi (PMASA-2019-5)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by a SQL injection  vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the phpMyAdmin application hosted on the remote web server is at least
4.7.7 and prior to 4.9.2. It is, therefore, affected by a SQL injection (SQLi) vulnerability. A remote attacker can
exploit this by using a crafted database or table name in the designer feature.

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2019-5/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin version 4.9.2 or later.
Alternatively, apply the patches referenced in the vendor advisories.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18622");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/phpMyAdmin");
  script_require_ports("Services/www", 80);

  exit(0);
}
include('http.inc');
include('vcf.inc');

port = get_http_port(default:80, php:TRUE);
appname = 'phpMyAdmin';
app_info = vcf::get_app_info(app:appname, port:port, webapp:TRUE);

constraints = [{'min_version':'4.7.7', 'fixed_version':'4.9.2'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{sqli:TRUE});
