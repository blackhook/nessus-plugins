#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42825);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/22");

  script_name(english:"Apple TV Detection");
  script_summary(english:"Looks for evidence of AppleTV in HTTP banner");

  script_set_attribute(attribute:"synopsis", value:"The remote host is a digital media receiver.");
  script_set_attribute(attribute:"description", value:
"The remote host is an Apple TV, a digital media receiver.");
  script_set_attribute(attribute:"see_also", value:"https://www.apple.com/apple-tv-4k/");
  script_set_attribute(attribute:"solution", value:
"Make sure that use of such devices is in line with your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_tv");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2009-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apple_airplay_web_detect.nbin");
  script_require_ports("Services/www", "Services/unknown", 3689);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");                                             
include("http5.inc");                                                  

http_disable_keep_alive();

ports = make_service_list("Services/www", "Services/unknown", 3689);
port = branch(ports);

if (!get_port_state(port))
    audit(AUDIT_PORT_CLOSED, port);

banner = get_http_banner(port:port);

if (isnull(banner)) 
{
  login = 'login?hsgid=00000000-0000-0000-0000-000000000000&hasFP=1';
  headers = make_array("Accept-Encoding", "gzip", "Client-DAAP-Version", "3.13", "Client-ATV-Sharing-Version", "1.2",
             "Client-iTunes-Sharing-Version", "3.15",  "Viewer-Only-Client", "1", "User-Agent", "Remote/1021");                    

  res = http_send_recv3(method:'GET', port:port, item:login, add_headers:headers, no_body:TRUE, version:11);
  if (empty_or_null(res) || empty_or_null(res[1])) audit(AUDIT_NO_BANNER, port);
  banner = res[1];                                              
}

if (isnull(banner)) audit(AUDIT_NO_BANNER, port);
daap = egrep(pattern:"^DAAP-Server: iTunes/[0-9][0-9.]+[a-z][0-9]+ \((Mac )?OS X\)", string:banner);
if ( "RIPT-Server: iTunesLib/" >< banner || daap)
{
  report = NULL;
  order = make_list();
  index = 0;
  report_array = make_array();          
  if (daap)
  {
    itunes = pregmatch(pattern:"^DAAP-Server: iTunes/([0-9][0-9.]+[a-z][0-9]+) \((Mac )?OS X\)", string:daap);
    if (!empty_or_null(itunes) && !empty_or_null(itunes[0]))
    {
      set_kb_item(name:"www/appletv/daap-server", value:itunes[1]);
      order[index] = "DAAP-Server";
      report_array["DAAP-Server"] = itunes[1];
      index++;
    }
  }
  set_kb_item(name:"www/appletv", value:TRUE);
  report = '\nDevice seems to be supporting AppleTV protocols:\n';                         
  report += report_items_str(report_items:report_array, ordered_fields:order);
  register_service(port:port, proto:"daap");
  security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
}
else exit(0, "The banner from the web server listening on port "+port+" does not look like that of an Apple TV.");
