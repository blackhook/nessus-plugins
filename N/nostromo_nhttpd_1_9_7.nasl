##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142137);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/08");

  script_cve_id("CVE-2019-16278");
  script_xref(name:"IAVA", value:"2020-A-0498");

  script_name(english:"Nostromo < 1.9.7 Remote Code Execution ");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its Server response header, the installed version of
Nostromo is prior to 1.9.7. It is, therefore, affected by remote code execution
 vulnerability.");
  # https://packetstormsecurity.com/files/155802/nostromo-1.9.6-Remote-Code-Execution.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aff750ca");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Nostromo version 1.9.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16278");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Nostromo Web Server RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Nostromo Directory Traversal Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nazgul:nostromo_nhttpd");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nostromo_nhttpd_detect.nbin");
  script_require_keys("installed_sw/nostromo");

  exit(0);
}

include('http.inc');
include('vcf.inc');

appname = 'nostromo';
port = get_http_port(default:80);
get_install_count(app_name:appname, exit_if_zero:TRUE);

app_info = vcf::get_app_info(app:appname, port: port, service:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  {'fixed_version' : '1.9.7'}
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
