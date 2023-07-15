#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
 script_id(17583);
 script_version("1.12");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");
 
  script_xref(name:"IAVT", value:"0001-T-0901");

 script_name(english:"Aventail ASAP Platform Management Console Detection");
 script_summary(english:"Aventail ASAP Management Console management");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is an SSL VPN appliance." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be an Aventail SSL VPN appliance, and it
allows connections to its web console management.  Letting attackers
know that you are using such a device will help them to focus their
attacks or will make them change their strategy. 

In addition to this, an attacker may attempt a brute-force attack to
log into the remote interface." );
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/21");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"x-cpe:/a:sonicwall:aventail_asap");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2005-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
 
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");

 script_require_ports(8443);
 exit(0);
}

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

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = 8443;
if(get_port_state(port))
{
 req = http_get(item:"/console/login.do", port:port);
 rep = https_get(request:req, port:port);
 if( rep == NULL ) exit(0);
 #<title>ASAP Management Console Login</title>
 if ("<title>ASAP Management Console Login</title>" >< rep)
 {
   security_note(port);
 }
}
