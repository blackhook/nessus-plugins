#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50860);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");

  script_name(english:"Pandora FMS Console Detection");

  script_set_attribute(attribute:"synopsis", value:
"A console for a monitoring application is running on the remote web
server.");
  script_set_attribute(attribute:"description", value:
"The web console for Pandora FMS, an open source monitoring system, is
running on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://pandorafms.com/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:artica:pandora_fms");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = 'Pandora FMS';
port = get_http_port(default:80, php:TRUE);

installed = FALSE;

dirs = make_list('/', '/pandora_console');
if (thorough_tests) dirs = list_uniq(make_list(dirs, cgi_dirs()));

# <br />v3.1 Build PC100609</td>
# <br />v3.1.1</td>
# <div id="ver_num">v5.1SP1</div>
patterns = make_list(
  '>v([^ ]+)[^<]*</td>',
  '<div id="ver_num">(v([^ ]+)[^<]*)</div>'
);

foreach dir (dirs)
{
  if (empty_or_null(dir)) continue;

  res = http_send_recv3(method:'GET', item:dir, port:port, follow_redirect:1);
  if (empty_or_null(res)) continue;
  if ('<title>Pandora FMS - the Flexible Monitoring System</title>' >< res[2])
  {
    foreach pattern (patterns)
    {
      match = eregmatch(string:res[2], pattern:pattern, icase:TRUE);
      if (match)
      {
        ver = match[1];
        break;
      }
      else ver = UNKNOWN_VER;
    }

    register_install(
      app_name : app,
      vendor : 'Artica',
      product : 'Pandora FMS',
      version  : ver,
      path     : dir,
      port     : port,
      webapp   : TRUE,
      cpe   : "cpe:/a:artica:pandora_fms"
    );

    installed = TRUE;

    if (!thorough_tests) break;
  }
}

if (installed) report_installs(app_name:app, port:port);
else audit(AUDIT_NOT_DETECT, app, port);
