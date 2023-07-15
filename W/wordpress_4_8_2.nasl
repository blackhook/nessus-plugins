#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103358);
  script_version("1.9");
  script_cvs_date("Date: 2019/03/29  9:51:59");

  script_cve_id(
    "CVE-2017-14718",
    "CVE-2017-14719",
    "CVE-2017-14720",
    "CVE-2017-14721",
    "CVE-2017-14722",
    "CVE-2017-14723",
    "CVE-2017-14724",
    "CVE-2017-14725",
    "CVE-2017-14726"
  );
  script_bugtraq_id(100912);

  script_name(english:"WordPress < 4.8.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the WordPress
application running on the remote web server is prior to 4.8.2.
It is, therefore, affected by multiple vulnerabilities :

  - A flaw in $wpdb->prepare() can create unsafe queries
    leading to potential SQL injection flaws with plugins
    and themes.

  - Multiple cross-site scripting (XSS) vulnerabilities
    exists due to improper sanitization of user-supplied
    input.  An unauthenticated, remote attacker can
    exploit this, via a specially crafted request, to
    execute arbitrary script code in a user's browser
    session. 

  - Multiple path traversal vulnerabilities exist in the
    file unzipping code and customizer. A remote attacker
    may be able to read arbitrary files subject to the
    privileges under which the web server runs.

  - An open redirect flaw exists on the user and term edit
    screens. A remote attacker can exploit this, by
    tricking a user into following a specially crafted link,
    to redirect a user to an arbitrary website.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://wordpress.org/news/2017/09/wordpress-4-8-2-security-and-maintenance-release/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dadf2914");
  script_set_attribute(attribute:"see_also", value:"https://codex.wordpress.org/Version_4.8.2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 4.8.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-14723");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/20");

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
  { "fixed_version":"3.7.22", "fixed_display" : "3.7.22 / 4.8.2" },
  { "min_version":"3.8", "fixed_version":"3.8.22", "fixed_display" : "3.8.22 / 4.8.2" },
  { "min_version":"3.9", "fixed_version":"3.9.20", "fixed_display" : "3.9.20 / 4.8.2" },
  { "min_version":"4.0", "fixed_version":"4.0.19", "fixed_display" : "4.0.19 / 4.8.2" },
  { "min_version":"4.1", "fixed_version":"4.1.19", "fixed_display" : "4.1.19 / 4.8.2" },
  { "min_version":"4.2", "fixed_version":"4.2.16", "fixed_display" : "4.2.16 / 4.8.2" },
  { "min_version":"4.3", "fixed_version":"4.3.12", "fixed_display" : "4.3.12 / 4.8.2" },
  { "min_version":"4.4", "fixed_version":"4.4.11", "fixed_display" : "4.4.11 / 4.8.2" },
  { "min_version":"4.5", "fixed_version":"4.5.10", "fixed_display" : "4.5.10 / 4.8.2" },
  { "min_version":"4.6", "fixed_version":"4.6.7", "fixed_display" : "4.6.7 / 4.8.2" },
  { "min_version":"4.7", "fixed_version":"4.7.6", "fixed_display" : "4.7.6 / 4.8.2" },
  { "min_version":"4.8", "fixed_version":"4.8.2", "fixed_display" : "4.8.2" }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{xss:TRUE, sqli:TRUE}
);
