#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from WordPress Security Advisory security-202.

include("compat.inc");

if (description)
{
  script_id(125680);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/04  8:43:57");

  script_name(english:"WordPress < 2.0.2 Multiple Cross-Site Scripting (XSS) Vulnerabilities");
  script_summary(english:"Checks the version of Wordpress.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple cross-site scripting (XSS)vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the WordPress application running on the remote web server is prior to
2.0.2. It is, therefore, affected by multiple cross-site scripting (XSS) vulnerabilities due to improper validation of
user-supplied input before returning it to users. An unauthenticated, remote attacker can exploit this, by convincing a
user to click a specially crafted URL, to execute arbitrary script code in a user's browser session.

Note the vulnerabilities fixed in this release were reported to and addressed by the WordPress development team without
disclosure. For more information see the linked security advisory");
  # https://wordpress.org/news/2006/03/security-202/ 
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?97a92950");
  script_set_attribute(attribute:"solution", value:"Upgrade to WordPress version 2.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for XSS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/WordPress", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);
app_info = vcf::get_app_info(app:'WordPress', port:port, webapp:TRUE);

constraints = [{ 'fixed_version' : '2.0.2' }];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});
