#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from WordPress Security Advisory wordpress-5-2-4-security-release.

include('compat.inc');

if (description)
{
  script_id(129849);
  script_version("1.5");
  script_cvs_date("Date: 2019/12/20");

  script_cve_id("CVE-2019-17671");

  script_name(english:"WordPress < 5.2.4 Multiple Vulnerabilities");
  script_summary(english:"Checks version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by 
  multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the WordPress application running on the remote web server is affected
by multiple vulnerabilities:
  - A cross-site scripting (XSS) vulnerability exists due to improper validation of user-supplied input before 
    returning it to users. An unauthenticated, remote attacker can exploit this, by convincing a user to click a 
    specially crafted URL, to execute arbitrary script code in a user's browser session.
  
  - An information disclosure vulnerability exists in Wordpress. An unauthenticated, remote attacker can exploit this 
    to disclose potentially sensitive information regarding unauthenticated posts.

  - A server-side request forgery vulnerability exists in Wordpress due to insufficient validation of URLs. An 
    unauthenticated, remote attacker can exploit this, by submitting specifically crafted URLs, to cause the server to 
    make requests on their behalf. Successful attacks may allow an attacker to request / update data which was not 
    intended to be accessed by a user of the application.
    
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/support/wordpress-version/version-5-2-4/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 5.2.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17671");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
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

app = 'WordPress';
get_install_count(app_name:app, exit_if_zero:TRUE);
port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
constraints = [{ 'max_version' : '5.2.3', 'fixed_version' : '5.2.4' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
