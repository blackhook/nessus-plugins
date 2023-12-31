#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81916);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_xref(name:"HP", value:"emr_na-c04553906");
  script_xref(name:"HP", value:"KM01351169");
  script_xref(name:"CERT", value:"867593");

  script_name(english:"HP Universal Configuration Management Database Data Flow Probe Gateway Cross-Site Tracing");
  script_summary(english:"Checks the UCMDB Probe Gateway for HTTP TRACE support.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross-site tracing
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HP Universal Configuration Management Database Data
Flow Probe Gateway running on the remote web server is affected by a
cross-site tracing vulnerability. A remote attacker can exploit this
to gain access to information in HTTP headers such as cookies and
authentication data.");
  # https://cf.passport.softwaregrp.com/hppcf/login.do?hpappid=206728_SSO_PRO&TYPE=33554433&REALMOID=06-000a5aa8-5753-18f0-a414-00bd0f78a02e&GUID=&SMAUTHREASON=0&METHOD=GET&SMAGENTNAME=$SM$o8O1D10%2ftKElla5TtPp65rDrT5k5G0zxLqneTAG5uysO3%2f7yctjoO3h5%2fRpka45ewHx55dv9NlXXfizkUS%2fjPEDb6N%2fozvWQ&TARGET=$SM$https%3a%2f%2fsoftwaresupport.softwaregrp.com%2fgroup%2fsoftwaresupport%2fsearch-result%2f-%2ffacetsearch%2fdocument%2fKM01351169
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d863b68e");
  script_set_attribute(attribute:"solution", value:
"Disable HTTP TRACE support.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:universal_configuration_management_database");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2021 Tenable Network Security, Inc.");

  script_dependencies("hp_ucmdb_probe_gateway_detect.nbin");
  script_require_keys("installed_sw/HP Universal Configuration Management Database Data Flow Probe Gateway");
  script_require_ports("Services/www", 1977, 8453);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("http.inc");

app_name = "HP Universal Configuration Management Database Data Flow Probe Gateway";

get_install_count(app_name:app_name, exit_if_zero:TRUE);

port = get_http_port(default:1977);

install = get_single_install(app_name:app_name, port:port);

url = build_url(port:port, qs:install['url']);

reply = http_send_recv3(item:'/', port:port, method:'TRACE', exit_on_fail:TRUE);

request = http_last_sent_request();
user_agent = egrep(pattern:"^User-Agent", string:request, icase:TRUE);

if (isnull(reply) || isnull(reply[0]) || reply[0] !~ "^HTTP/.* 200 ")
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url);

if (isnull(reply[2]) || reply[2] !~ "^TRACE / HTTP/1\.")
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url);

if (!isnull(user_agent) && (tolower(user_agent) >!< tolower(reply[2])))
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url);

security_report_v4(
  port       : port,
  severity   : SECURITY_WARNING,
  request    : make_list(request),
  output     : chomp(reply[0] + '\n' + reply[2]),
  line_limit : 20,
  generic    : TRUE,
  xss        : TRUE
);
exit(0);
