#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

# The descriptive text and package checks in this plugin were
# extracted from WordPress Security Advisory wordpress-5-9-2-security-maintenance-release.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159009);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/17");

  script_name(english:"WordPress 5.9 < 5.9.2 / 5.8 < 5.8.4 / 5.7 < 5.7.6 / 5.6 < 5.6.8 / 5.5 < 5.5.9 / 5.4 < 5.4.10 / 5.3 < 5.3.12 / 5.2 < 5.2.15 / 5.1 < 5.1.13 / 5.0 < 5.0.16 / 4.9 < 4.9.20 / 4.8 < 4.8.19 / 4.7 < 4.7.23 / 4.6 < 4.6.23 / 4.5 < 4.5.26 / 4.4 < 4.4.27 / 4.3 < 4.3.28 / 4.2 < 4.2.32 / 4.1 < 4.1.35 / 4.0 < 4.0.35 / 3.9 < 3.9.36 / 3.8 < 3.8.38 / 3.7 < 3.7.38");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by one or more vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"WordPress versions 5.9 < 5.9.2 / 5.8 < 5.8.4 / 5.7 < 5.7.6 / 5.6 < 5.6.8 / 5.5 < 5.5.9 / 5.4 < 5.4.10 / 5.3 < 5.3.12 /
5.2 < 5.2.15 / 5.1 < 5.1.13 / 5.0 < 5.0.16 / 4.9 < 4.9.20 / 4.8 < 4.8.19 / 4.7 < 4.7.23 / 4.6 < 4.6.23 / 4.5 < 4.5.26 /
4.4 < 4.4.27 / 4.3 < 4.3.28 / 4.2 < 4.2.32 / 4.1 < 4.1.35 / 4.0 < 4.0.35 / 3.9 < 3.9.36 / 3.8 < 3.8.38 / 3.7 < 3.7.38
are affected by one or more vulnerabilities");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/download/releases/");
  # https://wordpress.org/news/2022/03/wordpress-5-9-2-security-maintenance-release/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b97fee2e");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/support/wordpress-version/version-5-9-2/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 5.9.2, 5.8.4, 5.7.6, 5.6.8, 5.5.9, 5.4.10, 5.3.12, 5.2.15, 5.1.13, 5.0.16, 4.9.20, 4.8.19,
4.7.23, 4.6.23, 4.5.26, 4.4.27, 4.3.28, 4.2.32, 4.1.35, 4.0.35, 3.9.36, 3.8.38, 3.7.38 or later.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/WordPress", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app = 'WordPress';
get_install_count(app_name:app, exit_if_zero:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var port = get_http_port(default:80, php:TRUE);

var app_info = vcf::get_app_info(app:'WordPress', port:port, webapp:TRUE);

var constraints = [
  { 'min_version' : '3.7', 'fixed_version' : '3.7.38' },
  { 'min_version' : '3.8', 'fixed_version' : '3.8.38' },
  { 'min_version' : '3.9', 'fixed_version' : '3.9.36' },
  { 'min_version' : '4.0', 'fixed_version' : '4.0.35' },
  { 'min_version' : '4.1', 'fixed_version' : '4.1.35' },
  { 'min_version' : '4.2', 'fixed_version' : '4.2.32' },
  { 'min_version' : '4.3', 'fixed_version' : '4.3.28' },
  { 'min_version' : '4.4', 'fixed_version' : '4.4.27' },
  { 'min_version' : '4.5', 'fixed_version' : '4.5.26' },
  { 'min_version' : '4.6', 'fixed_version' : '4.6.23' },
  { 'min_version' : '4.7', 'fixed_version' : '4.7.23' },
  { 'min_version' : '4.8', 'fixed_version' : '4.8.19' },
  { 'min_version' : '4.9', 'fixed_version' : '4.9.20' },
  { 'min_version' : '5.0', 'fixed_version' : '5.0.16' },
  { 'min_version' : '5.1', 'fixed_version' : '5.1.13' },
  { 'min_version' : '5.2', 'fixed_version' : '5.2.15' },
  { 'min_version' : '5.3', 'fixed_version' : '5.3.12' },
  { 'min_version' : '5.4', 'fixed_version' : '5.4.10' },
  { 'min_version' : '5.5', 'fixed_version' : '5.5.9' },
  { 'min_version' : '5.6', 'fixed_version' : '5.6.8' },
  { 'min_version' : '5.7', 'fixed_version' : '5.7.6' },
  { 'min_version' : '5.8', 'fixed_version' : '5.8.4' },
  { 'min_version' : '5.9', 'fixed_version' : '5.9.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
