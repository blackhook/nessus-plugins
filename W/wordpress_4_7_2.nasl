#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96906);
  script_version("1.8");
  script_cvs_date("Date: 2019/03/29  9:51:59");

  script_cve_id(
    "CVE-2017-5610",
    "CVE-2017-5611",
    "CVE-2017-5612",
    "CVE-2017-1001000"
  );
  script_bugtraq_id(95816);
  script_xref(name:"EDB-ID", value:"41223");
  script_xref(name:"EDB-ID", value:"41224");
  script_xref(name:"EDB-ID", value:"41308");

  script_name(english:"WordPress < 4.7.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the WordPress
application running on the remote web server is prior to 4.7.2.
It is, therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists in the
    class-wp-press-this.php script due to a failure to
    properly restrict the user interface for assigning
    taxonomy terms. An authenticated, remote attacker can
    exploit this to disclose sensitive information.
    (CVE-2017-5610)

  - A SQL injection (SQLi) vulnerability exists in the
    class-wp-query.php script due to a failure to sanitize
    input to post type names. An unauthenticated, remote
    attacker can exploit this to inject or manipulate SQL
    queries in the back-end database, resulting in the
    disclosure or manipulation of arbitrary data.
    (CVE-2017-5611)

  - A cross-site scripting (XSS) vulnerability exists in the
    class-wp-posts-list-table.php script due to improper
    validation of input to the posts list table. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary script
    code in a user's browser session. (CVE-2017-5612)

  - A privilege escalation vulnerability exists in the REST
    API due to a failure to properly sanitize user-supplied
    input to the 'id' parameter when editing or deleting
    blog posts. An unauthenticated, remote attacker can
    exploit this issue to run arbitrary PHP code, inject
    content into blog posts, modify blog post attributes, or
    delete blog posts. (CVE-2017-1001000)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/news/2017/01/wordpress-4-7-2-security-release/");
  script_set_attribute(attribute:"see_also", value:"https://codex.wordpress.org/Version_4.7.2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 4.7.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5611");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/31");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
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
  { "min_version":"3.5", "fixed_version":"3.7.18", "fixed_display" : "3.7.18 / 4.7.2" },
  { "min_version":"3.8", "fixed_version":"3.8.18", "fixed_display" : "3.8.18 / 4.7.2" },
  { "min_version":"3.9", "fixed_version":"3.9.16", "fixed_display" : "3.9.16 / 4.7.2" },
  { "min_version":"4.0", "fixed_version":"4.0.15", "fixed_display" : "4.0.15 / 4.7.2" },
  { "min_version":"4.1", "fixed_version":"4.1.15", "fixed_display" : "4.1.15 / 4.7.2" },
  { "min_version":"4.2", "fixed_version":"4.2.12", "fixed_display" : "4.2.12 / 4.7.2" },
  { "min_version":"4.3", "fixed_version":"4.3.8", "fixed_display" : "4.3.8 / 4.7.2" },
  { "min_version":"4.4", "fixed_version":"4.4.7", "fixed_display" : "4.4.7 / 4.7.2" },
  { "min_version":"4.5", "fixed_version":"4.5.6", "fixed_display" : "4.5.6 / 4.7.2" },
  { "min_version":"4.6", "fixed_version":"4.6.3", "fixed_display" : "4.6.3 / 4.7.2" },
  { "min_version":"4.7", "fixed_version":"4.7.2", "fixed_display" : "4.7.2" }
];


vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{xss:TRUE, sqli:TRUE}
);
