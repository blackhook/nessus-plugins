#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104356);
  script_version("1.8");
  script_cvs_date("Date: 2019/03/29  9:51:59");

  script_cve_id(
    "CVE-2012-6707",
    "CVE-2016-9263",
    "CVE-2017-14723",
    "CVE-2017-16510"
  );
  script_bugtraq_id(101638);

  script_name(english:"WordPress < 4.8.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the WordPress
application running on the remote web server is prior to 4.8.3.
It is, therefore, affected by a SQL Injection vulnerability and other
vulnerabilities:

  - WordPress through 4.8.2 uses a weak MD5-based
    password hashing algorithm, which makes it easier for
    attackers to determine cleartext values by leveraging
    access to the hash values.

  - WordPress through 4.8.2, when domain-based
    flashmediaelement.swf sandboxing is not used, allows
    remote attackers to conduct cross-domain Flash
    injection (XSF) attacks by leveraging code contained
    within the wp-includes/js/mediaelement/flashmediaelement.swf
    file."
  );
  # https://wordpress.org/news/2017/10/wordpress-4-8-3-security-release/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?31328bd3");
  script_set_attribute(attribute:"see_also", value:"https://codex.wordpress.org/Version_4.8.3");
  # https://blog.ircmaxell.com/2017/10/disclosure-wordpress-wpdb-sql-injection-technical.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?73b7e2df");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 4.8.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-16510");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { "fixed_version":"3.7.23", "fixed_display" : "3.7.23 / 4.8.3" },
  { "min_version":"3.8", "fixed_version":"3.8.23", "fixed_display" : "3.8.23 / 4.8.3" },
  { "min_version":"3.9", "fixed_version":"3.9.21", "fixed_display" : "3.9.21 / 4.8.3" },
  { "min_version":"4.0", "fixed_version":"4.0.20", "fixed_display" : "4.0.20 / 4.8.3" },
  { "min_version":"4.1", "fixed_version":"4.1.20", "fixed_display" : "4.1.20 / 4.8.3" },
  { "min_version":"4.2", "fixed_version":"4.2.17", "fixed_display" : "4.2.17 / 4.8.3" },
  { "min_version":"4.3", "fixed_version":"4.3.13", "fixed_display" : "4.3.13 / 4.8.3" },
  { "min_version":"4.4", "fixed_version":"4.4.12", "fixed_display" : "4.4.12 / 4.8.3" },
  { "min_version":"4.5", "fixed_version":"4.5.11", "fixed_display" : "4.5.11 / 4.8.3" },
  { "min_version":"4.6", "fixed_version":"4.6.8", "fixed_display" : "4.6.8 / 4.8.3" },
  { "min_version":"4.7", "fixed_version":"4.7.7", "fixed_display" : "4.7.7 / 4.8.3" },
  { "min_version":"4.8", "fixed_version":"4.8.3", "fixed_display" : "4.8.3" }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{sqli:TRUE}
);
