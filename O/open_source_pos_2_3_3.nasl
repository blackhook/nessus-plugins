#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(122421);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2015-0299");

  script_name(english:"Open Source Point Of Sale Stored XSS");

  script_set_attribute(attribute:"synopsis", value:
"The Open Source Point of Sale (POS) application running on the
remote web server is vulnerable to an Stored XSS Vulnerability");
  script_set_attribute(attribute:"description", value:
"The Open Source Point of Sale (POS) application running on the
remote web server is vulnerable to a Stored XSS vulnerability.

  - A Stored cross-site scripting (XSS) vulnerability
  exists due to improper validation of user-supplied 
  input before returning it to users. An authenticated,
  remote attacker can exploit this, by can exploit this,
  via a specially crafted request, to execute arbitrary
  script code in a user's browser session.
  (CVE-2015-0299)");
  script_set_attribute(attribute:"see_also", value:"https://github.com/opensourcepos/opensourcepos");
  # http://packetstormsecurity.com/files/133737/Open-Source-Point-Of-Sale-2.3.1-Cross-Site-Scripting.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3662fb24");
  script_set_attribute(attribute:"see_also", value:"https://github.com/opensourcepos/opensourcepos/issues/39");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Open Source Point Of Sale 3.0.0 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0299");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:open_source_point_of_sale_project:open_source_point_of_sale");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("open_source_pos_detect.nbin");
  script_require_keys("Settings/ParanoidReport", "installed_sw/Open Source Point of Sale", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
} 

include('http.inc');
include('vcf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = 'Open Source Point of Sale';
port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:app_name, port:port, webapp:true);

constraints = [
  {'min_version':'2.3.1', 'fixed_version':'3.0.0'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:true});