#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102862);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-5198", "CVE-2017-5199");
  script_bugtraq_id(97090, 97094);
  script_xref(name:"IAVA", value:"2017-A-0259");

  script_name(english:"SolarWinds Log and Event Manager < 6.3.1 Hotfix 3 Jailbreak and Privilege Escalation");
  script_summary(english:"Checks the LEM version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the SolarWinds Log and
Event Manager installed on the remote host is prior to version 6.3.1 Hotfix 3.
It is, therefore, affected by multiple vulnerabilities :

  - Due to the program setting insecure permissions for management 
  scripts, a remote attacker to execute commands with elevated, 
  root privileges.(CVE-2017-5198)

  - A flaw exists in the mgrconfig.pl file that may allow 
  an authenticated remote attacker to escape from the sandbox 
  and execute commands with elevated privileges (CVE-2017-5199)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://blog.0xlabs.com/2017/03/solarwinds-lem-ssh-jailbreak-and.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?020871b2");
  # https://support.solarwinds.com/Success_Center/Log_Event_Manager_(LEM)/LEM_Documentation/Previous_Versions/Log_and_Event_Manager_LEM_6-3-1_Hotfix_3_ReadMe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c403f26");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SolarWinds Log and Event Manager version 6.3.1 Hotfix 3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5198");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:log_and_event_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("solarwinds_lem_detect.nbin");
  script_require_keys("installed_sw/SolarWinds Log and Event Manager");
  script_require_ports("Services/www", 8080, 8443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:8080);

app  = "SolarWinds Log and Event Manager";
install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);

dir        = install['path'];
version    = install['version'];
version_ui = install['display_version'];

install_url = build_url(port:port, qs:dir);

fix = "6.3.1";

if(ver_compare(ver:version, fix:fix, strict:FALSE) == 0 && report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, app, version_ui, port);

if ( ver_compare(ver:version, fix:fix, strict:FALSE) <= 0 )
{
  report =
  '\n  URL               : ' + install_url +
  '\n  Installed version : ' + version_ui +
  '\n  Fixed version     : ' + fix +
  '\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version_ui);
