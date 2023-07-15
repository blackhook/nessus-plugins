#%NASL_MIN_LEVEL 70300
#
# Copyright 2000 by Hendrik Scholz <hendrik@scholz.net>
#

# Changes by Tenable:
#
# - check for the error code in the first line only (RD)
# - compatible with no404.nasl (RD)
# - revised plugin title, modified solution (4/2/2009)

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
 script_id(10207);
 script_version("1.31");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");


 script_name(english:"Roxen Web Server Counter Module Crafted Request Saturation DoS");
 script_summary(english:"Roxen counter module installed ?");

 script_set_attribute(attribute:"synopsis", value:"The remote web server has a denial of service vulnerability.");
 script_set_attribute(attribute:"description", value:
"Roxen Challenger WebServer is running with the counter module
installed. Requesting large counter GIFs can lead to CPU exhaustion.
If the server does not support threads, this will prevent the server
from serving other clients.");
 script_set_attribute(attribute:"solution", value:"Disable the counter module.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

 script_set_attribute(attribute:"plugin_publication_date", value:"2000/01/03");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"vuln_publication_date", value:"2000/01/02");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2000-2021 Hendrik Scholz");

 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, embedded:TRUE);

banner = get_http_banner(port:port);
if ( ! banner || "Roxen" >!< banner ) exit(0);

if(get_port_state(port) && ! get_kb_item("Services/www/" + port + "/embedded") )
{
 name = string("www/no404/", port);
 no404 = tolower(get_kb_item(name));
 data = string("/counter/1/n/n/0/3/5/0/a/123.gif");
 data = http_get(item:data, port:port);
 soc = http_open_socket(port);
 if(soc)
 {
  send(socket:soc, data:data);
  line = recv_line(socket:soc, length:1024);
  buf = http_recv(socket:soc);
  buf = tolower(buf);
  must_see = "image";
  http_close_socket(soc);
  if(no404)
  {
    if(no404 >< buf)exit(0);
  }
  if((" 200 " >< line)&&(must_see >< buf))security_hole(port);
 }
}

