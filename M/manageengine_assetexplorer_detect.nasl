#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(63692);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"ManageEngine AssetExplorer Detection");
  script_summary(english:"Checks for ManageEngine AssetExplorer.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an asset management application.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts ManageEngine AssetExplorer, a web-based
asset management application.");
  script_set_attribute(attribute:"see_also", value:"https://www.manageengine.com/products/asset-explorer/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoho:manageengine_assetexplorer");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include('http.inc');
include('install_func.inc');
include('spad_log_func.inc');

var appname = 'ManageEngine AssetExplorer';
var port = get_http_port(default:8080);

var installs = 0;

var url = '/';
var res = http_get_cache(item:url, port:port, exit_on_fail:TRUE);
spad_log(message:'res: ' + obj_rep(res));
if (
  '<title>ManageEngine AssetExplorer</title>' >< res
)
{
  var display_version = NULL;
  var ver_pat   = ">version&nbsp;([0-9.]+[^<])</div>";
  var build_pat = "IncludeSDPScripts.js\?build=([0-9]+)";
  var new_build_pat = "src=..?/scripts/Login..?js..??([0-9]+)";
  var matches = pgrep(pattern:ver_pat, string:res);
  var item, match, version;

  if (!empty_or_null(matches))
  {
    foreach match (split(matches, keep:FALSE))
    {
      item = pregmatch(pattern:ver_pat, string:match);
      if (!isnull(item))
      {
        display_version = item[1];
        spad_log(message:'Setting display_version to: ' + obj_rep(display_version));
        break;
      }
    }
  }

  if (!empty_or_null(display_version))
  {
    matches = pgrep(pattern:build_pat, string:res);
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        item = pregmatch(pattern:build_pat, string:match);
        if (!isnull(item))
        {
          display_version += " Build " + item[1];
          version = item[1];
          spad_log(message:'Setting display_version to: ' + obj_rep(display_version) + ' and version to: ' + obj_rep(version));
          break;
        }
      }
    }
  }

  # new style
  if (empty_or_null(version))
  {
    spad_log(message:'No version match, trying new style');
    match = pregmatch(pattern:new_build_pat, string:res);
    if (!empty_or_null(match))
    {
      spad_log(message:'match: ' + obj_rep(match));
      version = match[1];
      if (empty_or_null(display_version))
        display_version = version;
    }
  }

  # Save info about the install.
  register_install(
    vendor : "Zoho",
    product : "ManageEngine AssetExplorer",
    app_name : appname,
    path : "",
    port : port,
    version : version,
    display_version:display_version,
    cpe : "cpe:/a:zoho:manageengine_assetexplorer",
    webapp: TRUE
  );

  installs++;

}
if (installs == 0) audit(AUDIT_WEB_APP_NOT_INST, appname, port);

# Report findings.
report_installs(port:port);
