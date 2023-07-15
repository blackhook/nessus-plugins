#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105371);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-14589", "CVE-2017-14590");
  script_bugtraq_id(102188, 102193);

  script_name(english:"Atlassian Bamboo 6.1.x < 6.1.6 / 6.2.x < 6.2.5 Incorrect Permission Check RCE");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of
Atlassian Bamboo running on the remote host is 6.1.x prior to 6.1.6 or
6.2.x prior to 6.2.5. It is, therefore, affected by multiple 
remote code execution vulnerabilities.");
  # https://confluence.atlassian.com/bamboo/bamboo-security-advisory-2017-12-13-939939816.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?33dffba7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Bamboo version 6.1.6 / 6.2.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-14590");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:bamboo");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bamboo_detect.nbin");
  script_require_keys("installed_sw/bamboo", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8085);

  exit(0);
}

include("http.inc");
include("vcf.inc");

app = "bamboo";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8085);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { "min_version" : "6.1", "max_version" : "6.1.5", "fixed_version" : "6.1.6" },
  { "min_version" : "6.2", "max_version" : "6.2.4", "fixed_version" : "6.2.5" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
