##
# (C) Tenable Network Security, Inc.
##

include("compat.inc");

if (description)
{
  script_id(57799);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"CodeMeter WebAdmin Detection");
  script_summary(english:"Looks for evidence of CodeMeter WebAdmin.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a copy protection application.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts CodeMeter WebAdmin, a web-based tool for working with CodeMeter hardware and software
based copy protection technology.

Note: for accurate results from this plugin and those that depend on it, you may need to enable the CodeMeter WebAdmin
ports (22352, 22350) in your Nessus scan.");
  script_set_attribute(attribute:"see_also", value:"https://www.wibu.com/products/codemeter.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wibu:codemeter_runtime");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 22350, 22352);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('http.inc');
include('install_func.inc');
include('debug.inc');

##
# Checks to detect a CodeMeter WebAdmin from HTML content
#
# @param str HTML content
#
# @return TRUE if a CodeMeter WebAdmin was detected, FALSE otherwise
##
function codemeter_check(str)
{
  if (
    'title>CodeMeter | WebAdmin' >< str ||
    (
      'WIBU-SYSTEMS HTML Served Page' >< str &&
      'onclick="return OnScanNetwork()"' >< str &&
      '<!-- WebAdmin Version -->' >< str
    ) ||
    (
      'Server: WIBU-SYSTEMS HTTP Server' >< str &&
      'WIBU-SYSTEMS HTML Served Page' >< str &&
      'getCookie("com.wibu.cm.webadmin.lang")' >< str

    ) ||
    (
      '<title title="t-dashboard">WebAdmin | Dashboard</title>' >< str &&
      '<h1><span class="t-main-heading-codemeter">CodeMeter</span>' >< str &&
      '<span class="t-main-heading-webadmin">WebAdmin</span>' >< str
    ) ||
    (
      'CmWebAdminSession=' >< str &&
      'href="/dashboard.html">Moved Permanently</a>' >< str
    )
  )
      return TRUE;
  return FALSE;
}

##
# Checks to detect a CodeMeter WebAdmin from HTML content
# based on file full pattern
# format like 6.70.3164.455
#
##
function codemeter_match_full_pat()
{
  var matches = NULL;
  var match = NULL;
  var item = NULL;
  matches = pgrep(pattern:ver_full_pat, string:res);
  if (matches)
  {
    dbg::log(src:SCRIPT_NAME, msg:'Matched with ver_full_pat');
    foreach match (split(matches, keep:FALSE))
    {
      item = pregmatch(pattern:ver_full_pat, string:match);
      if (!isnull(item))
      {
        version = item[1];
        break;
      }
    }
  }
}

##
# Checks to detect a CodeMeter WebAdmin from HTML content
# based on ui pattern
# format like "Version 6.30d of Sep/29/2016 (Build 2280)"
#
##
function codemeter_match_ui_pattern()
{
  var matches = NULL;
  var match = NULL;
  var item = NULL;
  var last = NULL;
  matches = pgrep(pattern:ver_ui_pat, string:res);
  if (matches)
  {
    dbg::log(src:SCRIPT_NAME, msg:'Matched with ver_ui_pat');
    foreach match (split(matches, keep:FALSE))
    {
      item = pregmatch(pattern:ver_ui_pat, string:match);
      if (!isnull(item))
      {
        if (isnull(version))
        {
          extra = make_array('Server Version', item[0]);
          version = item[1];

          if (isnull(item[2])) version_ui = version;
          else version_ui = strcat(version, item[2]);

          if (isnull(item[5])) item[5] = 0;

          if (isnull(item[2])) last = 500;
          else last = 500 + ord(item[2]) - ord('a') + 1;

          version = join(sep:'.', item[1], item[5], last);
        }
        else
        {
          version_ui = item[1];
          if (!isnull(item[2])) version_ui = strcat(version_ui, item[2]);
        }
        break;
      }
    }
  }
}

##
# Checks to detect a CodeMeter WebAdmin from HTML content
# based on ui pattern
# format like "Version 6.70a of 26. September 2018 (Build 3164)"
##
function codemeter_match_ui_pattern2()
{
  var matches = NULL;
  var match = NULL;
  var item = NULL;
  var last = NULL;
  matches = pgrep(pattern:ver_server_version, string:res);
  if (matches)
  {
    dbg::log(src:SCRIPT_NAME, msg:'Matched with ver_server_version');
    foreach match (split(matches, keep:FALSE))
      {
        item = pregmatch(string:match, pattern:ver_server_version);
        if (!isnull(item))
        {
          if(isnull(version))
          {
            extra = make_array('Server Version', item[0]);
            version = item[1];

            if (isnull(item[2])) version_ui = version;
            else version_ui = strcat(version, item[2]);

            if (isnull(item[6])) item[6] = 0;

            if (isnull(item[2])) last = 500;
            else last = 500 + ord(item[2]) - ord('a') + 1;

            version = join(sep:'.', item[1], item[6], last);
          }
        }
        else
        {
          version_ui = item[1];
          if (!isnull(item[5])) version_ui = strcat(version_ui, item[5]);
        }
        break;
      }
  }
}

##
# Checks to detect a CodeMeter WebAdmin from HTML content
# based on ui pattern
# format like Version 7.10
##
function codemeter_match_webadmin_version()
{
  var matches = NULL;
  var match = NULL;
  var item = NULL;
  if (isnull(version) && 'WebAdmin Version' >< res)
  {
    matches = pgrep(pattern:ver_short_pat, string:res);
    if (matches)
    {
      dbg::log(src:SCRIPT_NAME, msg:'Matched with ver_short_pat');
      foreach match (split(matches, keep:FALSE))
      {
        item = pregmatch(pattern:ver_short_pat, string:match);
        if (!isnull(item))
        {
          version = item[1];
          break;
        }
      }
    }
  }
}

var app = 'CodeMeter';
var installed = FALSE;

var port = get_http_port(default:22352, embedded:TRUE);

var url = '/';

var ver_full_pat = "<!-- FileVersion=([0-9][0-9.]+) -->";
var ver_ui_pat = "Version ([0-9][0-9.]+)([a-z])? of (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/[0-9]+/[0-9]+( \(Build ([0-9]+)\))?";
var ver_short_pat = "Version ([0-9][0-9.]+) of (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)";
var ver_server_version = "Version ([0-9][0-9.]+)([a-z])? of ([0-9]{1,}.) (January|February|March|April|May|June|July|August|September|October|November|December) ([0-9]{4}) \(Build ([0-9]+)?\)";

# Get cache for /
var res = http_get_cache(item:url, port:port, exit_on_fail:TRUE);
# If it's a redirect, follow the redirect
if('HTTP/1.1 301 Moved Permanently' >< res)
{
  var r = http_send_recv3(
    method          : 'GET',
    item            : url,
    port            : port,
    exit_on_fail    : TRUE,
    follow_redirect : 1
  );

  res  = r[0] + r[1] + '\r\n' + r[2];
}
# Detect CodeMeter WebAdmin
# If detected, try to grab the version
if (codemeter_check(str:res))
{
  dbg::log(src:SCRIPT_NAME, msg:'CodeMeter HTML identified');
  var version = NULL;
  var version_ui = NULL;
  var extra = make_array();

  codemeter_match_full_pat();

  # Use UI pattern as backup if full pattern fails
  # Note: We're checking this regardless of whether or
  # not we already have a version because the UI
  # version contains the format that the user is likely
  # to see in vendor documentation.
  codemeter_match_ui_pattern();

  # For at least Version 6.70a there is a new pattern
  codemeter_match_ui_pattern2();

  # nb: as a last resort, use the WebAdmin version.
  codemeter_match_webadmin_version();

  # Version check plugins will be using the UI
  # version as the display value. Ensure that it
  # contains a value before registering
  if (isnull(version_ui)) version_ui = version;

  # Be more specific with the display version.
  # Try to display as much info about the version
  # as possible.
  if (version_ui != version) version_ui = version_ui + ' (' + version + ')';

  register_install(
    vendor  : "WIBU",
    product : "CodeMeter Runtime",
    app_name : app,
    display_version : version_ui,
    version : version,
    port    : port,
    path    : '/',
    webapp  : TRUE,
    cpe  : 'cpe:/a:wibu:codemeter_runtime',
    extra: extra
  );

  if(isnull(version)) report_xml_tag(tag:'codemeter_webadmin', value:base64(str:res));
  else installed = TRUE;
}

if (installed) report_installs(app_name:app, port:port);
else audit(AUDIT_WEB_APP_NOT_INST, app, port);
