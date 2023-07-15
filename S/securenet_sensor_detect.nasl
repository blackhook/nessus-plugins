#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(18534);
 script_version("1.10");
 script_cvs_date("Date: 2019/11/22");
 
 script_name(english:"Intrusion.com SecureNet Sensor Detection");

 script_set_attribute(attribute:"synopsis", value:
"A intrusion detection/prevention system is installed on the remote
host." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be an Intrusion.com SecureNet sensor on 
this port." );
 script_set_attribute(attribute:"solution", value:
"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/20");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"x-cpe:/a:intrusion.com:securenet");
script_set_attribute(attribute:"asset_inventory", value:"True");
script_end_attributes();

 script_summary(english:"Checks for Intrusion.com SecureNet sensor console");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 script_require_keys("www/apache");
 script_require_ports(443);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

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

port = 443;

if(get_port_state(port))
{
  req1 = http_get(item:"/main/login.php?action=login", port:port);
  req = https_get(request:req1, port:port);

  if("<title>WBI Login</title>" >< req)
  {
    security_note(port);
  }
}
