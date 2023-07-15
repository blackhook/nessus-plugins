#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135757);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2007-6752");

  script_name(english:"Drupal 7.x < 7.13 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running a PHP application that is affected by
a cross-site request forgery vulnerabilit. A csrf vulnerability exists allowing 
remote attackers to hijack the authentication of arbitrary users for requests 
that end a session via the user/logout URI. (CVE-2007-6752)");
  script_set_attribute(attribute:"see_also", value:"https://packetstormsecurity.com/files/110404/drupal712-xsrf.txt");
  # https://packetstormsecurity.com/files/110404/drupal712-xsrf.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e959b46");
  script_set_attribute(attribute:"see_also", value:"https://www.exploit-db.com/exploits/18564");
  # https://www.exploit-db.com/exploits/18564
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?39d78cc8");
  script_set_attribute(attribute:"see_also", value:"https://groups.drupal.org/node/216314");
  # https://groups.drupal.org/node/216314
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ed24bf3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 7.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-6752");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(352);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("drupal_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/Drupal", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}
include("vcf.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:"Drupal", port:port, webapp:true);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { "min_version" : "7.0", "fixed_version" : "7.13" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{"xsrf" : TRUE});
