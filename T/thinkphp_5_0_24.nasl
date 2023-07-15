#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155964);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2019-9082");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"ThinkPHP < 5.0.24 RCE");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of ThinkPhP installed on the remote host is prior to 5.0.24. It is, therefore, affected by a remote code 
execution vulnerability. An unauthenticated, remote attacker can exploit this to execute arbitrary php code 
through multiple parameters.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.exploit-db.com/exploits/48333");
  script_set_attribute(attribute:"see_also", value:"https://github.com/xiayulei/open_source_bms/issues/33");
  # https://packetstormsecurity.com/files/157218/ThinkPHP-5.0.23-Remote-Code-Execution.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7be44ca0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ThinkPHP version 5.0.24 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9082");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ThinkPHP Multiple PHP Injection RCEs');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:thinkphp:thinkphp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("thinkphp_detect.nbin");
  script_require_keys("installed_sw/ThinkPHP");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app_name = "ThinkPHP";
var port = get_http_port(default:80, php:TRUE);
var app_info = vcf::get_app_info(app:app_name, port:port);

constraints = [
  { 'fixed_version':'5.0.24' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
