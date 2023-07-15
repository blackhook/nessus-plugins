#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15614);
 script_version("1.15");

 script_name(english:"Check Point InterSpect Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running an internet security gateway." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running Check Point InterSpect,
an internet security gateway. 

The Nessus host is likely to have been put in quarantine, 
its activity will be dropped for 30 minutes by default." );
 script_set_attribute(attribute:"see_also", value:"https://www.checkpoint.com/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/03");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/12");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"x-cpe:/a:checkpoint:interspect");
script_set_attribute(attribute:"asset_inventory", value:"True");
script_end_attributes();

 
 script_summary(english:"Detect Check Point InterSpect");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Service detection");
 script_dependencie("httpver.nasl", "broken_web_server.nasl");
 script_require_ports(80,3128);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80, embedded:TRUE);

if(!get_port_state(port))exit(0, "Port "+port+" is closed.");

r = http_get_cache_ka(item:"/", port:port);
if (isnull(r)) exit(1, "The web server on port "+port+" failed to respond.");
if (egrep(pattern:"<TITLE>Check Point InterSpect - Quarantine</TITLE>.*Check Point InterSpect", string:r))
   {
    security_note(port);
    set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
   }
