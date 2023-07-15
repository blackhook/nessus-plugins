#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65915);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"MongoDB Web Interface Detection");
  script_summary(english:"Detects the MongoDB Web Interface.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a web interface for a database
system.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running the MongoDB Web Admin Interface. This
interface lists information of interest to administrators of MongoDB,
a document-oriented database system.");
  script_set_attribute(attribute:"see_also", value:"https://docs.mongodb.com/ecosystem/tools/http-interfaces/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mongodb:mongodb");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 28017);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "MongoDB Web Admin Interface";

port = get_http_port(default:28017, embedded:FALSE);

res = http_send_recv3(item:"/",
                      port:port,
                      method:"GET",
                      exit_on_fail:TRUE);

installs = 0;

if (
  res[2] =~ "<title>[^<]*mongod[^<]*</title>" &&
  "List all commands" >< res[2] &&
  "buildInfo" >< res[2]
)
{
  version = UNKNOWN_VER;

  # <pre>db version v2.4.1
  item = eregmatch(pattern:'<pre>db version v([^\n, ]+)',
                   string: res[2]);

  if (!isnull(item)) version = item[1];

  register_install(
    vendor:"MongoDB",
    product:"MongoDB",
    app_name:"mongodb_web",
    port:port,
    path:"/",
    version:version,
    cpe:"cpe:/a:mongodb:mongodb",
    webapp:TRUE
  );

  installs++;
}

if (installs == 0)
  audit(AUDIT_WEB_APP_NOT_INST, appname, port);

report_installs(port:port);
