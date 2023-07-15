#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42339);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"Adobe ColdFusion Detection");
  script_summary(english:"Looks for the ColdFusion admin settings page.");

  script_set_attribute(attribute:"synopsis", value:
"A web application platform was detected on the remote web server.");
  script_set_attribute( attribute:"description", value:
"Adobe ColdFusion (formerly Macromedia ColdFusion), a rapid application
development platform, is running on the remote web server.");
  script_set_attribute(attribute:"see_also", value:"https://www.adobe.com/products/coldfusion-family.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/02");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 8500);

  exit(0);
}

include('http.inc');
include('webapp_func.inc');

var app = 'ColdFusion';
var port = get_http_port(default:80);

# The installer always puts ColdFusion in the same location
var dir  = '/CFIDE';
var item = '/administrator/settings/version.cfm';
var url  = dir + item;
var installs = 0;
var ver = NULL;

# 8.x, 9.x use an image on login page for version display
var login_ver_pats = make_list(
  "ColdFusion .*([0-9]{4}) Release",          # 2021
  'Version:[\r\n]+ ([0-9,_hf]+)</strong><br', # 6.x
  'Version:[\r\n]+([0-9,_hf]+)</strong>'      # 7.x
);

var sysinfo_ver_pats = make_list(
  '<td[^>]*>[\r\n \t]+Version[\r\n \t]+</td>[\r\n \t]+<td[^>]*>[\r\n \t]+([0-9,_hf]+)[\r\n \t]+</td>', # 11.x
  'Version[\r\n]+.*&nbsp;</p>[\r\n]+.*</td>[\r\n]+.*class="color-row">[\r\n]+.*&nbsp; ([0-9,_hf]+)', # 6.x
  'Version[\r\n\t]+</td>[\r\n\t]+<td nowrap.*[\r\n\t]+([0-9,_hf]+)' # 7.x, 8.x, 9.x
);

var res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail: TRUE);
if ('ColdFusion' >!< res[2]) audit(AUDIT_WEB_APP_NOT_INST, app, port);

var pat, vmatches;
if ('<title>ColdFusion Administrator Login</title>' >< res[2])
{
  foreach pat (login_ver_pats)
  {
    vmatches = pregmatch(pattern:pat, string:res[2]);
    if (vmatches)
    {
      ver = str_replace(string:vmatches[1], find:',', replace:'.');
      break;
    }
  }
}

# No admin password is set
if ('<title>System Information</title>' >< res[2] &&
  (
    'METHOD="POST" onSubmit="return _CF_checkCFForm' >< res[2] ||
    'method="post" onSubmit="return _CF_checkCFForm' >< res[2] ||
    'method="post" onsubmit="return _CF_checkCFForm' >< res[2]
  )
)
{
  set_kb_item(name:'www/'+port+'/coldfusion/no_admin_password', value:TRUE);
  foreach pat (sysinfo_ver_pats)
  {
    vmatches = pregmatch(pattern:pat, string:res[2]);
    if (vmatches)
    {
      ver = str_replace(string:vmatches[1], find:',', replace:'.');
      break;
    }
  }
}

# If we failed to detect version 6 or 7, try to detect 8 or 9.
if (empty_or_null(ver))
{
  res = http_send_recv3(
    method : 'GET',
    port   : port,
    item   : '/CFIDE/adminapi/base.cfc?wsdl'
  );

  if (!empty_or_null(res))
  {
    vmatches = pregmatch(string:res[2], pattern:"<!--.*ColdFusion version ([0-9,]+)-->");
    if (!empty_or_null(vmatches)) ver = str_replace(string:vmatches[1], find:',', replace:'.');
  }
}

# try requesting a different page to get version 10
if (empty_or_null(ver))
{
  res = http_send_recv3(
    method : 'GET',
    port   : port,
    item   : '/CFIDE/services/pdf.cfc?wsdl'
  );

  if (!empty_or_null(res))
  {
    vmatches = pregmatch(string:res[2], pattern:"<!--.*ColdFusion version ([0-9,]+)-->");
    if (!empty_or_null(vmatches)) ver = str_replace(string:vmatches[1], find:',', replace:'.');
  }
}

# Try at least seeing if we have any info to show it's version 11
if (empty_or_null(ver))
{
   res = http_send_recv3(
    method : 'GET',
    port   : port,
    item   : '/CFIDE/administrator/help/index.html'
  );

  if (!empty_or_null(res))
  {
    vmatches = pregmatch(string:res[2], pattern:'Configuring and Administering ColdFusion ([0-9]+)');
    if (!empty_or_null(vmatches) && !isnull(vmatches[1])) ver = vmatches[1];
  }
}

if (empty_or_null(ver)) ver = UNKNOWN_VER;

register_install(
  vendor   : "Adobe",
  product  : "ColdFusion",
  app_name : app,
  path     : dir,
  port     : port,
  version  : ver,
  cpe      : 'cpe:/a:adobe:coldfusion',
  webapp   : TRUE
);

# Report findings.
report_installs(port:port);
