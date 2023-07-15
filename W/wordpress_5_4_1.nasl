#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from WordPress Security Advisory wordpress-5-4-1.

include('compat.inc');

if (description)
{
  script_id(136179);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/19");

  script_xref(name:"IAVA", value:"2020-A-0191-S");

  script_name(english:"WordPress < 5.4.1");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server
is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"WordPress versions 5.4.0 and earlier are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/news/2020/04/wordpress-5-4-1/");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/support/wordpress-version/version-5-4-1/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 5.4.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for XSS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/WordPress", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

app = 'WordPress';
get_install_count(app_name:app, exit_if_zero:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:'WordPress', port:port, webapp:TRUE);

constraints = [
  { 'fixed_version' : '5.4.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});
