#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154728);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2018-15811", "CVE-2018-18325");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"DNN (DotNetNuke) 9.2 <= 9.2.2 Weak Encryption Algorithm Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP.NET application that is affected by weak encryption algorithm vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of DNN Platform (formerly DotNetNuke) running on the remote host is 9.2 through 9.2.2 uses a weak 
encryption algorithm to protect input parameters.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.dnnsoftware.com/community/security/security-center");
  script_set_attribute(attribute:"solution", value:
"Upgrade to DNN Platform version 9.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-18325");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'DotNetNuke Cookie Deserialization Remote Code Excecution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dotnetnuke:dotnetnuke");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dotnetnuke_detect.nasl");
  script_require_keys("installed_sw/DNN");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http.inc');
include('vcf.inc');

var port = get_http_port(default:80, asp:TRUE);
var app_info = vcf::get_app_info(app:'DNN', port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
      {'min_version' : '9.2.0', 'max_version': '9.2.2', 'fixed_version' : '9.3.1' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
