#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(102978);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2013-3437");
  script_xref(name:"CISCO-BUG-ID", value:"CSCud80179");

  script_name(english:"Cisco Unified Operations Manager 8.6 SQL Injection Vulnerability");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The monitoring application hosted on the remote web server has
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Cisco
Unified Operations Manager on the remote host has multiple
vulnerabilities as described in CSCud80179.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=30153");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/Cisco-SA-20130719-CVE-2013-3437
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83413812");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCud80179
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?844a06c8");
  script_set_attribute(attribute:"solution", value:
"Contact the vendor or apply the 
      workarounds mentioned in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_operations_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_uom_detect.nasl");
  script_require_keys("www/cisco_uom");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("cisco_func.inc");

port = get_http_port(default:443);
install = get_install_from_kb(appname:'cisco_uom', port:port, exit_on_fail:TRUE);

cbi = "CSCud80179";

login_page = install['dir'] + get_kb_item('/tmp/cuom/' + port + '/loginpage');
login_url = build_url(qs:login_page, port:port);
version = install['ver'];

if (version == UNKNOWN_VER)
  exit(1, 'Unable to identify the Cisco Unified Operations Manager version at ' + login_url + '.');

if (version == "8.6.0" || version == "8.6")
{
  security_report_cisco(
      port     : 0,
      severity : SECURITY_WARNING,
      version  : version,
      bug_id   : cbi,
      fix      : "See advisory"
      );
}
else exit(0, 'The Cisco Unified Operations Manager ' + version + ' install at ' + login_url + ' is not affected.');

