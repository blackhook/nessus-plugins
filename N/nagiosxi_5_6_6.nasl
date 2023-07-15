#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154935);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2019-15949");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Nagios XI < 5.6.6 RCE");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web application affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"Nagios XI before 5.6.6 allows remote command execution as root. The exploit requires access to the server as the nagios
user, or access as the admin user via the web interface. The getprofile.sh script, invoked by downloading a system 
profile (profile.php?cmd=download), is executed as root via a passwordless sudo entry; the script executes 
check_plugin, which is owned by the nagios user. A user logged into Nagios XI with permissions to modify plugins, or 
the nagios user on the server, can modify the check_plugin executable and insert malicious commands to execute as root.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.nagios.com/downloads/nagios-xi/change-log/");
  script_set_attribute(attribute:"see_also", value:"https://www.nagios.com/products/security/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Nagios XI 5.6.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15949");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Nagios XI Prior to 5.6.6 getprofile.sh Authenticated Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nagios:nagios_xi");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2023 Tenable Network Security, Inc.");

  script_dependencies("nagios_enterprise_detect.nasl");
  script_require_keys("installed_sw/nagios_xi");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http_func.inc');
include('vcf_extras.inc');

var app = 'nagios_xi';

# Get the ports that web servers have been found on.
var port = get_http_port(default:80, embedded:TRUE);

var app_info = vcf::nagiosxi::get_app_info(port:port);

var constraints = [
    {'fixed_version': '5.6.6'}
];

vcf::nagiosxi::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, default_fix:'5.6.6');
