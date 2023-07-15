#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##


include('deprecated_nasl_level.inc');
include("compat.inc");


if (description)
{
  script_id(55447);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"ManageEngine SupportCenter Plus Detection");
  script_summary(english:"Looks for evidence of ManageEngine SupportCenter");

  script_set_attribute(attribute:"synopsis", value:"The remote web server hosts a customer support application.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts ManageEngine SupportCenter Plus, a web-
based customer support application written in Java."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.manageengine.com/products/support-center/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:manageengine:supportcenter_plus");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include('http.inc');
include('webapp_func.inc');
include('spad_log_func.inc');
include('install_func.inc');

var port = get_http_port(default:8080);
var appname = 'ManageEngine SupportCenter';
var old_appname = 'manageengine_supportcenter';

var installs = NULL;
var url = '/';

var res = http_get_cache(item:url, port:port, exit_on_fail:TRUE);
spad_log(message:'res: ' + obj_rep(res));
if (
  'nter both username and password to '  >< res &&
  pgrep(pattern:'title>.*ManageEngine SupportCenter', string:res)
)
{
  var version = UNKNOWN_VER;

  var build_pat = "src=..?/scripts/(common|IncludeSDPScripts|Login)..?js..??([0-9]+)";
  var matches = pgrep(pattern:build_pat, string:res);
  spad_log(message:'build_pat matches: ' + obj_rep(matches));
  if (!empty_or_null(matches))
  {
    foreach match (split(matches, keep:FALSE))
    {
      var item = pregmatch(pattern:build_pat, string:match);
      if (!isnull(item))
      {
        spad_log(message:'item: ' + obj_rep(item));
        var build = item[2];
        if (strlen(build) == 4)
        {
          version = strcat(build[0], '.', build[1], '.', build[2], ' Build ', build);
          break;
        }
        else if (strlen(build) == 5)
        {
          version = strcat(substr(build, 0, 1), '.', build[2], '.', build[3], ' Build ', build);
          break;
        }
      }
    }
  }

  # Save info about the install.
  var installs = add_install(
    appname  : old_appname,
    installs : installs,
    port     : port,
    dir      : '',
    ver      : version,
    cpe      : 'cpe:/a:manageengine:supportcenter_plus'
  );

  # Add new vcf-friendly register install for version checks
  register_install(
    vendor           : "ManageEngine",
    product          : "SupportCenter Plus",
    app_name         : appname,
    path             : url,
    port             : port,
    version          : build,
    display_version : version,
    cpe              :  'cpe:/a:manageengine:supportcenter_plus'
  );

}
if (isnull(installs))
  exit(0, 'ManageEngine SupportCenter Plus was not detected on the web server on port '+port+'.');

report_installs(app_name:old_appname, port:port);
