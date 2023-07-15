#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104104);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-1092");
  script_xref(name:"EDB-ID", value:"42541");

  script_name(english:"IBM OpenAdmin Tool welcomeService.php Remote Code Execution");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is
affected by a code injection flaw.");
  script_set_attribute(attribute:"description", value:
"The version of OpenAdmin Tool installed on the remote host is
affected by a remote code execution vulnerability. The
welcomeService.php file offers a SOAP interface, which does not
validate code passed to the 'saveHomePage' method, allowing a
remote attacker to save arbitrary code into 'config.php', which is
accessible to remote users. A remote attacker could exploit this
issue to execute arbitrary code with the privileges of the target
service.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22002897");
  script_set_attribute(attribute:"see_also", value:"https://blogs.securiteam.com/index.php/archives/3210");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 3.16 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'IBM OpenAdmin Tool SOAP welcomeServer PHP Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cpe:/a:ibm:openadmin_tool");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2022 Tenable Network Security, Inc.");

  script_dependencies("openadmin_tool_detect.nasl");
  script_require_keys("installed_sw/openadmin_tool");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("webapp_func.inc");

#getting the http port to connect to 
appname = 'openadmin_tool';
app = "OpenAmdin Tool";

get_install_count(app_name:appname, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(app_name:appname, port:port);

ver = install['version'];

#Suppose to be this is the safe version to use 
fix = '3.16';
if (ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
  report =
    'Installed version : ' + ver + '\n' +
    'Fixed version     : ' + fix;

  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, app, ver);
