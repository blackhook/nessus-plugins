#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

# The descriptive text and package checks in this plugin were
# extracted from WordPress Security Advisory wordpress-5-8-2-security-and-maintenance-release.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155026);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/10");

  script_name(english:"WordPress 5.8 < 5.8.2 / 5.7 < 5.7.4 / 5.6 < 5.6.6 / 5.5 < 5.5.7 / 5.4 < 5.4.8 / 5.3 < 5.3.10 / 5.2 < 5.2.13");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by one or more vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"WordPress versions 5.8 < 5.8.2 / 5.7 < 5.7.4 / 5.6 < 5.6.6 / 5.5 < 5.5.7 / 5.4 < 5.4.8 / 5.3 < 5.3.10 / 5.2 < 5.2.13 are
affected by one or more vulnerabilities");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/download/releases/");
  # https://wordpress.org/news/2021/11/wordpress-5-8-2-security-and-maintenance-release/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?edc9270b");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/support/wordpress-version/version-5-8-2/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 5.8.2, 5.7.4, 5.6.6, 5.5.7, 5.4.8, 5.3.10, 5.2.13 or later.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '5.2', 'fixed_version' : '5.2.13' },
  { 'min_version' : '5.3', 'fixed_version' : '5.3.10' },
  { 'min_version' : '5.4', 'fixed_version' : '5.4.8' },
  { 'min_version' : '5.5', 'fixed_version' : '5.5.7' },
  { 'min_version' : '5.6', 'fixed_version' : '5.6.6' },
  { 'min_version' : '5.7', 'fixed_version' : '5.7.4' },
  { 'min_version' : '5.8', 'fixed_version' : '5.8.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
