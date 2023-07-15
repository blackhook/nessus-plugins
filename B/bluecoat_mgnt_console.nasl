#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(16363);
 script_version("1.11");
 script_cvs_date("Date: 2019/09/25  9:17:09");

 script_name(english:"Blue Coat ProxySG Console Management Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is a firewall." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be a Blue Coat ProxySG appliance, an
enterprise-class firewall, and it allows connections to its web
console management application.

Letting attackers know the type of firewall in use may help them focus
their attacks against the networks it protects." );
 script_set_attribute(attribute:"see_also", value:"https://www.symantec.com" );
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/10");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:proxysg");
script_end_attributes();


 script_summary(english:"Checks for Blue Coat web console management");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Firewalls");
 script_dependencie("http_version.nasl");

 script_require_ports(8082);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("global_settings.inc");
function https_get(port, request)
{
    local_var result, soc;

    if(get_port_state(port))
    {

         soc = open_sock_tcp(port, transport:ENCAPS_SSLv23);
         if(soc)
         {
            send(socket:soc, data:string(request,"\r\n"));
            result = http_recv(socket:soc);
            close(soc);
            return(result);
         }
    }
}

port = 8082;
if(get_port_state(port))
{
  req = https_get(request:http_get(item:"/Secure/Local/console/logout.htm", port:port), port:port);
  if("<title>Blue Coat Systems  - Logout</title>" >< req)
  {
    security_note(port);
  }
}
