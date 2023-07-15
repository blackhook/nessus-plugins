#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(38183);
  script_version("1.8");

  script_name(english:"ClearSpace Detection");
  script_summary(english:"Detects Jive ClearSpace"); 

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a social networking site");

 script_set_attribute(attribute:"description", value:
"The remote web server is running Jive ClearSpace, a social
networking site letting users manage wikis, publish blog entries
and discuss between each other." );
 script_set_attribute(attribute:"see_also", value:"https://www.jivesoftware.com/");
 script_set_attribute( attribute:"solution", value:
"Make sure the proper access controls are put in place");

  script_set_attribute(
    attribute:"risk_factor",
    value:"None"
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/27");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:jive:clearspace");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);

# Loop through directories.
dirs = make_list("/", "/clearspace/");
foreach dir (dirs)
{
  url = string(dir, "admin/login.jsp?url=main.jsp");
  res = http_send_recv3(method:'GET', item:url, port:port);
  if (isnull(res)) exit(0);
  if ( "jive-loginVersion" >< res[2] )
  {
   s = strstr(res[2], "jive-loginVersion");#, res[2]);
   if ( ! s ) continue;
   s = split(s, keep:FALSE);
   version = strcat(s[0], s[1], s[2], s[3], s[4]);
   if ( ereg(pattern:"Clearspace *[0-9.]+ .*", string:version) )
   {
    version = ereg_replace(pattern:".*Clearspace[ 	]*([0-9.]+) .*", string:version, replace:"\1");
    set_kb_item(name:"www/" + port + "/clearspace", value:version + " under " + dir );
    security_note(port:port, extra:"Jive ClearSpace " + version + " is installed under " + dir);

    register_install(
     vendor:"Jive",
     product:"ClearSpace",
     app_name: "Jive ClearSpace",
     path: url,
     webapp: TRUE,
     version: version,
     cpe:"x-cpe:/a:jive:clearspace");

    exit(0);
   }
  }
}
