#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(112019);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-0464");
  script_bugtraq_id(105159);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj86072");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180828-dcnm-traversal");
  script_xref(name:"TRA", value:"TRA-2018-20");
  script_xref(name:"IAVA", value:"2018-A-0284");

  script_name(english:"Cisco Prime Data Center Network Manager < 11.0(1) Download Servlet Path Traversal Vulnerability");
  script_summary(english:"Checks the DCNM version number.");

  script_set_attribute(attribute:"synopsis", value:
"A network management system running on the remote host is affected by
a path traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Cisco Prime Data
Center Network Manager (DCNM) installed on the remote host is prior
to 11.0(1). It is, therefore, affected by a path traversal
vulnerability in the Download servlet. An authenticated, remote
attacker can exploit this, via a specially craft HTTP request, to
read arbitrary files and create arbitrary directories.

Note that this plugin determines if DCNM is vulnerable by checking the
version number displayed in the web interface. However, the web
interface is not available in older versions of DCNM.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180828-dcnm-traversal
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?568b3472");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Prime Data Center Network Manager version 11.0(1) or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0464");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_data_center_network_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_prime_dcnm_web_detect.nasl");
  script_require_keys("installed_sw/cisco_dcnm_web", "Settings/ParanoidReport");
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
install = get_single_install(app_name:app_id, port:port, exit_if_unknown_ver:TRUE);

url = build_url(qs:install['path'], port:port);
ver = install['version'];

match = pregmatch(string:ver, pattern:"^([0-9.]+)\(([^)]+)\)");
if (isnull(match)) exit(1, "Failed to parse the version ("+ver+").");

major = match[1];
build = match[2];

version = major + '.' + build;

if(report_paranoia < 2 && (ver_compare(ver:version, minver:'10.3.1', fix:'10.4.2', strict:FALSE) < 1)) audit(AUDIT_PARANOID);

if (ver_compare(ver:version, minver:"10.0.1", fix:'10.4.2', strict:FALSE) < 1)
{

  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : 11.0(1)' +
    '\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}

else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, ver);
