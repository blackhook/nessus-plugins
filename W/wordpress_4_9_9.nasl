#
# (C) Tenable Network Security, Inc.
#
include('compat.inc');

if (description)
{
  script_id(125597);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/30 13:24:46");

  script_cve_id("CVE-2017-1000600", "CVE-2018-1000773");
  script_bugtraq_id(105305, 105306);

  script_name(english:"WordPress < 4.9.9 Remote Code Execution Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the WordPress application running on the remote web server is prior to 
4.9.9. It is, therefore, affected by remote command execution vulnerabilities in its thumbnail processing component due
to insufficient validation of user input. An authenticated, remote attacker can exploit this, by uploading a 
malicious thumbnail, to execute arbitrary commands. (CVE-2017-1000600, CVE-2018-1000773).

Note that WordPress originally issued a fix for CVE-2017-1000600 but this fix was deemed insufficient and exploitation
was still possible. Thus, CVE-2018-1000773 was opened and addressed in version 4.9.9.");
  # https://wordpress.org/support/wordpress-version/version-4-9-9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3b77cfec");
  script_set_attribute(attribute:"solution", value:"Upgrade to WordPress version 4.9.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1000600");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/30");

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

constraints = [{'fixed_version':'4.9.9' }];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
