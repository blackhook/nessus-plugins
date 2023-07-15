#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(34851);
 script_version("1.11");
 
 script_name(english: "Polycom Videoconferencing Unit Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is a Polycom videoconferencing unit." );
 script_set_attribute(attribute:"description", value:
"The remote web server provides an access to a Polycom
videoconferencing unit." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/11/21");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"x-cpe:/h:polycom:video_conferencing_unit");
script_set_attribute(attribute:"asset_inventory", value:"True");
script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
script_set_attribute(attribute:"hardware_inventory", value:"True");
script_set_attribute(attribute:"os_identification", value:"True");
script_end_attributes();

 
 script_summary(english: "Detect Polycom");
 
 script_category(ACT_GATHER_INFO); 
 script_copyright(english:"This script is Copyright (C) 2008-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english: "Web Servers");
 script_dependencies("http_version.nasl");
 script_require_ports(80);
 exit(0);
}

include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");
include("http.inc");

function test(port)
{
  local_var page, server, r;

  server = get_http_banner(port: port, exit_on_fail: 1);
  if ("NetPort Software" >!< server && "Viavideo-Web" >!< server) return 0;

  page = http_get_cache(port: port, item: "/", exit_on_fail: 1);
  if ("Polycom" >< page || "polycom" >< page) return 1;
  r = http_send_recv3(method: "GET", item: "/u_indexmain.htm", port: port, exit_on_fail: 1);
  page = r[2];
  if ("Polycom" >< page || "polycom" >< page) return 1;
  return 0;
}
  
port = get_http_port(default: 80);

if (test(port: port))
{
 security_note(port: port);
 set_kb_item(name: 'www/'+port+'/polycom', value: TRUE);

 app = "Polycom Videoconferencing Unit";
 version = UNKNOWN_VER;
 path = "/";
 cpe = "x-cpe:/h:polycom:video_conferencing_unit";

 register_install(
   vendor   : "Polycom",
   product  : "Video Conferencing Unit",
   app_name : app,
   version  : version,
   path     : path,
   port     : port,
   webapp   : true,
   cpe      : cpe
 );
}
