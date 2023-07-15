#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87921);
  script_version("1.12");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id("CVE-2016-1564");
  script_bugtraq_id(79914);

  script_name(english:"WordPress < 4.4.1 class-wp-theme.php XSS");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"The PHP application running on the remote web server is affected by
a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the WordPress
application running on the remote web server is prior to 4.4.1.
It is, therefore, affected by a cross-site scripting (XSS)
vulnerability due to improper validation of user-supplied input to the
file wp-includes/class-wp-theme.php before returning it in error
messages. A remote attacker can exploit this, via a crafted request,
to execute arbitrary script code in the user's browser session.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://wpvulndb.com/vulnerabilities/8358");
  # https://wordpress.org/news/2016/01/wordpress-4-4-1-security-and-maintenance-release/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f9eafbe");
  script_set_attribute(attribute:"see_also", value:"https://codex.wordpress.org/Version_4.4.1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 4.4.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1564");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/WordPress", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

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
  { "min_version":"3.7", "fixed_version":"3.7.12", "fixed_display" : "3.7.12 / 4.4.1" },
  { "min_version":"3.8", "fixed_version":"3.8.12", "fixed_display" : "3.8.12 / 4.4.1" },
  { "min_version":"3.9", "fixed_version":"3.9.10", "fixed_display" : "3.9.10 / 4.4.1" },
  { "min_version":"4.0", "fixed_version":"4.0.9", "fixed_display" : "4.0.9 / 4.4.1" },
  { "min_version":"4.1", "fixed_version":"4.1.9", "fixed_display" : "4.1.9 / 4.4.1" },
  { "min_version":"4.2", "fixed_version":"4.2.6", "fixed_display" : "4.2.6 / 4.4.1" },
  { "min_version":"4.3", "fixed_version":"4.3.2", "fixed_display" : "4.3.2 / 4.4.1" },
  { "min_version":"4.4", "fixed_version":"4.4.1", "fixed_display" : "4.4.1" }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{xss:TRUE}
);
