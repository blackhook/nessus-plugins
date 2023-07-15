#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50449);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");

  script_name(english:"Atlassian FishEye Detection");

  script_set_attribute(attribute:"synopsis", value:
"A version control system interface was detected on the remote web
server.");
  script_set_attribute(attribute:"description", value:
"Atlassian FishEye, a web interface for version control systems such as
Subversion, Git, and Perforce, is running on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://www.atlassian.com/software/fisheye");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:fisheye");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8060);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:8060);

found = 0;
app = 'FishEye';

pattern = '\\(Version:([0-9.]+)';
dirs = cgi_dirs();  # by default it's served out of the root

foreach dir (dirs)
{
  version = NULL;
  url = dir + '/admin/login-default.do';
  res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

  if ('>Administration log in to FishEye' >< res[2])
  {
    match = eregmatch(string:res[2], pattern:pattern, icase:TRUE);
    if (!isnull(match)) version = match[1];
    if ( (isnull(version)) || (version == '') ) version = UNKNOWN_VER;

    register_install(
      app_name : tolower(app),
      vendor : 'Atlassian',
      product : 'Fisheye',
      path     : dir,
      port     : port,
      version  : version,
      cpe      : "cpe:/a:atlassian:fisheye",
      webapp   : TRUE
    );
    found++;

    if (!thorough_tests) break;
  }
}

if (found == 0)
  audit(AUDIT_WEB_APP_NOT_INST, app, port);

report_installs(port:port);
