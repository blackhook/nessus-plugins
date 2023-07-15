#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104479);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-12262");
  script_bugtraq_id(101647);
  script_xref(name:"CISCO-BUG-ID", value:"CSCve89638");
  script_xref(name:"IAVA", value:"2017-A-0321");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20171101-apicem");

  script_name(english:"Cisco APIC-EM 1.x < 1.5 Unauthorized Access (credentialed check)");
  script_summary(english:"Checks the APIC-EM version number.");

  script_set_attribute(attribute:"synopsis", value:
"A network management system running on the remote host is affected 
by an unauthorized access vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Cisco Application
Policy Infrastructure Controller Enterprise Module (APIC-EM)
application running on the remote host is 1.x prior to 1.5. It is,
therefore, affected by a vulnerability within the firewall 
configuration of the Cisco Application Policy Infrastructure 
Controller Enterprise Module (APIC-EM) that could allow an 
unauthenticated, adjacent attacker to gain privileged access to 
services only available on the internal network of the device.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171101-apicem
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8a7b78fe");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.5 as referenced in Cisco Security
Advisory cisco-sa-20171101-apicem.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12262");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:application_policy_infrastructure_controller_enterprise_module");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_apic_webui_detect.nbin");
  script_require_keys("installed_sw/Cisco APIC-EM");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Cisco APIC-EM";

get_install_count(app_name:app, exit_if_zero:TRUE);

fix = "1.5";
flag = 0;

port = get_http_port(default:443);
install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);

url = build_url(qs:install['path'], port:port);
ver = install['version'];

report = NULL;
if (ver =~ "^1\.")
  flag++;

if (flag && ver_compare(ver:ver, fix:fix) == -1)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix;
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
  exit(0);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, ver);
