#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129696);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-12922");

  script_name(english:"phpMyAdmin <= 4.9.1 Cross-Site Request Forgery Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by a cross-site request forgery vulnerability");
  script_set_attribute(attribute:"description", value:
"A cross-site request forgery (XSRF) vulnerability exists in the 
Setup page of phpMyAdmin. A remote attacker can exploit this by 
tricking a user into visiting a specially crafted web page, allowing 
the attacker to delete any server in the setup page by creating a 
fake hyperlink containing the malicious request it wants the 
victim's web browser to execute. 

Note that Nessus has not tested for this issue but has instead 
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/files/4.9.1/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin version 4.9.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12922");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(352);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/phpMyAdmin", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('http.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:'phpMyAdmin', port:port, webapp:TRUE);

constraints = [{'fixed_version' : '4.9.1'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
