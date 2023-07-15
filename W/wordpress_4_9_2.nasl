#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106304);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2018-5776");
  script_bugtraq_id(102730);

  script_name(english:"WordPress < 4.9.2 MediaElement.js Flash Fallback XSS");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by
a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the WordPress
application running on the remote web server is prior to 4.9.2.
It is, therefore, affected by a cross-site scripting vulnerability.");
  # https://wordpress.org/news/2018/01/wordpress-4-9-2-security-and-maintenance-release/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d2f97df");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 4.9.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5776");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/WordPress", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("vcf.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = "WordPress";
port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { "min_version":"3.7", "fixed_version":"3.7.25", "fixed_display" : "3.7.25 / 4.9.2" },
  { "min_version":"3.8", "fixed_version":"3.8.25", "fixed_display" : "3.8.25 / 4.9.2" },
  { "min_version":"3.9", "fixed_version":"3.9.23", "fixed_display" : "3.9.23 / 4.9.2" },
  { "min_version":"4.0", "fixed_version":"4.0.22", "fixed_display" : "4.0.22 / 4.9.2" },
  { "min_version":"4.1", "fixed_version":"4.1.22", "fixed_display" : "4.1.22 / 4.9.2" },
  { "min_version":"4.2", "fixed_version":"4.2.19", "fixed_display" : "4.2.19 / 4.9.2" },
  { "min_version":"4.3", "fixed_version":"4.3.15", "fixed_display" : "4.3.15 / 4.9.2" },
  { "min_version":"4.4", "fixed_version":"4.4.14", "fixed_display" : "4.4.14 / 4.9.2" },
  { "min_version":"4.5", "fixed_version":"4.5.13", "fixed_display" : "4.5.13 / 4.9.2" },
  { "min_version":"4.6", "fixed_version":"4.6.10", "fixed_display" : "4.6.10 / 4.9.2" },
  { "min_version":"4.7", "fixed_version":"4.7.9", "fixed_display" : "4.7.9 / 4.9.2" },
  { "min_version":"4.8", "fixed_version":"4.8.5", "fixed_display" : "4.8.5 / 4.9.2" },
  { "min_version":"4.9", "fixed_version":"4.9.2", "fixed_display" : "4.9.2" }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{xss:TRUE}
);
