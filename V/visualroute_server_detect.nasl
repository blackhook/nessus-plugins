#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10744);
 script_version ("1.22");


 name["english"] = "VisualRoute Web Server Detection";
 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"A VisualRoute server is listening on the remote port." );
 script_set_attribute(attribute:"description", value:
"VisualRoute is a web-based solution which allows unauthenticated users
to perform traceroutes against arbitrary hosts on the Internet." );
 script_set_attribute(attribute:"solution", value:
"Disable this service if you do not use it." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/08/29");
 script_cvs_date("Date: 2019/11/22");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"x-cpe:/a:visualroute:visualroute");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_end_attributes();

 summary["english"] = "Extracts the banner of the remote visual route server";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8000);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 1);

r = http_send_recv3(method:"GET", item:"/", port:port, exit_on_fail: 1);

h = parse_http_headers(status_line: r[0], headers: r[1]);
if (isnull(h)) exit(1, "Could not parse HTTP headers");
srv = h["server"];

if ("VisualRoute" >< srv)
 {
  report = 'The remote version of VisualRoute is ' + srv;
  security_note(port:port, extra:report);
  set_kb_item(name:"www/" + port + "/embedded", value:TRUE);
 }

