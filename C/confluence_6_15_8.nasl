#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(128548);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-3394");

  script_name(english:"Atlassian Confluence 6.1.x < 6.6.16 / 6.7.x < 6.13.7 / 6.14.x < 6.15.8 Local File Disclosure Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by a local file disclosure vulnerability");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Atlassian Confluence 
application running on the remote host is 6.1.x prior to 6.6.16, 6.7.x 
prior to 6.13.7, 6.14.x prior to 6.15.8. It is, therefore, affected 
by a local file disclosure vulnerability which exists in page export 
component. An authenticated, remote attacker with AddPage space 
permission can exploit this to read arbitrary files in the 
<install-directory>/confluence/WEB-INF directory.  

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://confluence.atlassian.com/doc/confluence-security-advisory-2019-08-28-976161720.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d906d699");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version 6.6.16, 6.13.7, 6.13.4, 6.14.3, 6.15.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3394");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:confluence");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("confluence_detect.nasl");
  script_require_keys("installed_sw/confluence", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8080, 8090);

  exit(0);
}

include('vcf.inc');
include('http.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = 'confluence';

port = get_http_port(default:80);

app_info = vcf::get_app_info(app:app_name, port:port, webapp:true);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  {"min_version": "6.1.0",  "fixed_version": "6.6.16", "fixed_display": "6.6.16 / 6.13.7 / 6.15.8" },
  {"min_version": "6.7.0",  "fixed_version": "6.13.7", "fixed_display": "6.6.16 / 6.13.7 / 6.15.8" },
  {"min_version": "6.14.0", "fixed_version": "6.15.8", "fixed_display": "6.6.16 / 6.13.7 / 6.15.8" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
