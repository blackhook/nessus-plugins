#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119601);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/26");

  script_cve_id("CVE-2018-19968", "CVE-2018-19970");

  script_name(english:"phpMyAdmin 4.x < 4.8.4 Multiple Vulnerabilities (PMASA-2018-6) (PMASA-2018-8)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the phpMyAdmin
application hosted on the remote web server is 4.x prior to
4.8.4. It is, therefore, affected by multiple vulnerabilities:

  - An arbitrary file read vulnerability exists in the transformation
    feature. An authenticated, remote attacker can exploit this to
    read arbitrary files and disclose sensitive information.
    (CVE-2018-19968)

  - A cross-site scripting (XSS) vulnerability exists due to improper
    validation of user-supplied input before returning it to users.
    An unauthenticated, remote attacker can exploit this, by
    convincing a user to click a specially crafted URL, to execute
    arbitrary script code in a user's browser session.
    (CVE-2018-19970)

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2018-6/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2018-8/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin version 4.8.4 or later.
Alternatively, apply the patches referenced in the vendor advisories.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19970");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-19968");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/phpMyAdmin", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}
include("http.inc");
include("vcf.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

appname = "phpMyAdmin";

app_info = vcf::get_app_info(app:appname, port:port, webapp:TRUE);

constraints = [{"min_version":"4.0", "fixed_version":"4.8.4"}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});
