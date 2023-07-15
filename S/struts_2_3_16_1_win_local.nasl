#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 9/12/2018. Use struts_2_3_16_1.nasl instead

include('compat.inc');

if (description)
{
  script_id(81105);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/25");

  script_cve_id("CVE-2014-0050", "CVE-2014-0094");
  script_bugtraq_id(65400, 65999);
  script_xref(name:"CERT", value:"719225");

  script_name(english:"Apache Struts 2.0.0 < 2.3.16.1 Multiple Vulnerabilities (credentialed check) (Deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated and replaced by 
struts_2_3_16_1.nasl (plugin ID 117393).");
  script_set_attribute(attribute:"see_also", value:"http://struts.apache.org/docs/version-notes-23161.html");
  script_set_attribute(attribute:"see_also", value:"http://struts.apache.org/docs/s2-020.html");
  script_set_attribute(attribute:"solution", value:"N/A.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts ClassLoader Manipulation Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/30");

  
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2020 Tenable Network Security, Inc.");

  script_dependencies("struts_detect_win.nbin", "struts_config_browser_detect.nbin");
  script_require_keys("installed_sw/Apache Struts");

  exit(0);
}
exit(0, "This plugin has been deprecated. Use struts_2_3_16_1.nasl (plugin ID 117393) instead.");

include("install_func.inc");

app = "Apache Struts";

install = get_single_install(app_name : app);
version = install['version'];
path  = install['path'];
appname = install['Application Name'];

fix = "2.3.16.1";
report = NULL;

if (version == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_APP_VER, ("the " + app + " application, " + appname + ", found at " + path + ","));
if (
  version =~ "^2\." &&
  ver_compare(ver:version, fix:fix, strict:FALSE) == -1
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  report +=
    '\n  Application       : ' + appname +
    '\n  Physical path     : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
}

if (!isnull(report))
{
  port = get_kb_item("SMB/transport");
  if (isnull(port)) port = 445;

  if (report_verbosity > 0) security_warning(port:port, extra:report);
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, (app + " 2 application, " + appname + ","), version, path);
