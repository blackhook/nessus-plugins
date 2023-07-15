#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96606);
  script_version("1.13");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id(
    "CVE-2016-10033",
    "CVE-2016-10045",
    "CVE-2017-5487",
    "CVE-2017-5488",
    "CVE-2017-5489",
    "CVE-2017-5490",
    "CVE-2017-5491",
    "CVE-2017-5492",
    "CVE-2017-5493"
  );
  script_bugtraq_id(
    95108,
    95130,
    95391,
    95397,
    95399,
    95401,
    95402,
    95406,
    95407
  );
  script_xref(name:"EDB-ID", value:"40968");
  script_xref(name:"EDB-ID", value:"40969");
  script_xref(name:"EDB-ID", value:"40970");
  script_xref(name:"EDB-ID", value:"40964");
  script_xref(name:"EDB-ID", value:"40986");

  script_name(english:"WordPress < 4.7.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the WordPress
application running on the remote web server is prior to 4.7.1.
It is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists in the
    PHPMailer component in the class.phpmailer.php script
    due to improper handling of sender email addresses. An
    unauthenticated, remote attacker can exploit this to
    pass extra arguments to the sendmail binary, potentially
    allowing the attacker to execute arbitrary code.
    (CVE-2016-10033, CVE-2016-10045)

  - An information disclosure vulnerability exists in the
    REST API implementation due to a failure to properly
    restrict listings of post authors. An unauthenticated,
    remote attacker can exploit this, via a
    wp-json/wp/v2/users request, to disclose sensitive
    information. (CVE-2017-5487)

  - Multiple cross-site scripting (XSS) vulnerabilities
    exist in the update-core.php script due to improper
    validation of input to the plugin name or version
    header. An unauthenticated, remote attacker can exploit
    these, via a specially crafted request, to execute
    arbitrary script code in a user's browser session.
    (CVE-2017-5488)

  - A cross-site request forgery (XSRF) vulnerability exists
    due to improper handling of uploaded Flash files. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted Flash file, to hijack the
    authentication of users. (CVE-2017-5489)

  - A cross-site scripting (XSS) vulnerability exists in the
    class-wp-theme.php script due to improper validation of
    input when handling theme name fallback. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary script
    code in a user's browser session. (CVE-2017-5490)

  - A security bypass vulnerability exists in the
    wp-mail.php script due to improper validation of mail
    server names. An unauthenticated, remote attacker can
    exploit this, via a spoofed mail server with the
    'mail.example.com' name, to bypass intended security
    restrictions. (CVE-2017-5491)

  - A cross-site request forgery (XSRF) vulnerability exists
    in the widget-editing accessibility-mode feature due to
    a failure to require multiple steps, explicit
    confirmation, or a unique token when performing certain
    sensitive actions for HTTP requests. An unauthenticated,
    remote attacker can exploit this, by convincing a user
    to follow a specially crafted URL, to hijack the
    authentication of users or cause them to edit widgets.
    (CVE-2017-5492)

  - A security bypass vulnerability exists in the
    ms-functions.php script due to the use of weak
    cryptographic security for multisite activation keys. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted site sign-up or user sign-up, to
    bypass intended access restrictions. (CVE-2017-5493)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://wordpress.org/news/2017/01/wordpress-4-7-1-security-and-maintenance-release/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dede5367");
  script_set_attribute(attribute:"see_also", value:"https://codex.wordpress.org/Version_4.7.1");
  script_set_attribute(attribute:"see_also", value:"https://core.trac.wordpress.org/query?milestone=4.7.1");
  # http://www.eweek.com/security/wordpress-4.7.1-updates-for-8-security-issues
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f07608c3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 4.7.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-10033");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHPMailer Sendmail Argument Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/18");

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
  { "fixed_version":"3.7.17", "fixed_display" : "3.7.17 / 4.7.1" },
  { "min_version":"3.8", "fixed_version":"3.8.17", "fixed_display" : "3.8.17 / 4.7.1" },
  { "min_version":"3.9", "fixed_version":"3.9.15", "fixed_display" : "3.9.15 / 4.7.1" },
  { "min_version":"4.0", "fixed_version":"4.0.14", "fixed_display" : "4.0.14 / 4.7.1" },
  { "min_version":"4.1", "fixed_version":"4.1.14", "fixed_display" : "4.1.14 / 4.7.1" },
  { "min_version":"4.2", "fixed_version":"4.2.11", "fixed_display" : "4.2.11 / 4.7.1" },
  { "min_version":"4.3", "fixed_version":"4.3.7", "fixed_display" : "4.3.7 / 4.7.1" },
  { "min_version":"4.4", "fixed_version":"4.4.6", "fixed_display" : "4.4.6 / 4.7.1" },
  { "min_version":"4.5", "fixed_version":"4.5.5", "fixed_display" : "4.5.5 / 4.7.1" },
  { "min_version":"4.6", "fixed_version":"4.6.2", "fixed_display" : "4.6.2 / 4.7.1" },
  { "min_version":"4.7", "fixed_version":"4.7.1", "fixed_display" : "4.7.1" }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{xss:TRUE, xsrf:TRUE}
);
