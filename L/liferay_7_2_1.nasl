#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155678);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/26");

  script_cve_id("CVE-2020-7961");
  script_xref(name:"IAVA", value:"2021-A-0296-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Liferay Portal 6.2.x < 6.2.5 / 7.0.x < 7.0.6 / 7.1.x < 7.1.3 / 7.2.x < 7.2.1 RCE");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by a remote code execution vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Liferay Portal installed on the remote host is affected by a remote code execution vulnerability in its
JSON web services component. An unauthenticated, remote attacker can exploit this to bypass authentication and execute 
arbitrary commands. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://portal.liferay.dev/learn/security/known-vulnerabilities/-/asset_publisher/HbL5mxmVrnXW/content/id/117954271
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e5493d5e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Liferay Portal 6.2.5, 7.0.6, 7.1.3, 7.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7961");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Liferay Portal Java Unmarshalling via JSONWS RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:liferay:liferay_portal");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("liferay_detect.nasl");
  script_require_keys("installed_sw/liferay_portal");
  script_require_ports("Services/www", 8080);

  exit(0);
}
include('http.inc');
include('vcf.inc');

var port = get_http_port(default:8080);
var app_info = vcf::get_app_info(app:'liferay_portal', webapp:TRUE, port:port);

var constraints = [
  {'min_version': '6.2.0' , 'fixed_version': '6.2.5'},
  {'min_version': '7.0.0' , 'fixed_version': '7.0.6'},
  {'min_version': '7.1.0' , 'fixed_version': '7.1.3'},
  {'min_version': '7.2.0' , 'fixed_version': '7.2.1'}
];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_HOLE
);
