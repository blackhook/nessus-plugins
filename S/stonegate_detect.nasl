#%NASL_MIN_LEVEL 70300
#
# This script was written by Holger Heimann <hh@it-sec.de>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, enhanced description (7/06/09)
# - Updated to use compat.inc, Changed risk factor, updated security_note to use 'extra' arg (11/20/2009)


include('deprecated_nasl_level.inc');
include("compat.inc");

if(description)
{
  script_id(11762);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"StoneGate Firewall Client Authentication Detection");

  script_set_attribute(attribute:"synopsis", value:
"A firewall client is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"A StoneGate firewall client login is detected.
 
This service should not be available from the internet or 
a non-administrative internal network.");
  script_set_attribute(attribute:"solution", value:
"Restrict incoming traffic to this port");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:stonesoft:stonegate_ips");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2003-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/SG_ClientAuth", 2543);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");


function test_stonegate(port)
{
  local_var match, r;
  r = get_kb_banner(port: port, type: "spontaneous");
  if ( ! r ) return 0;
  match = egrep(pattern:"(StoneGate firewall|SG login:)", string : r); 
  if(match)
	return(r);
  else	
  	return(0);
}


## Heres the real dialog:
#
#	 telnet www.xxxxxx.de 2543
#	Trying xxx.xxx.xxx.xxx ...
#	Connected to www.xxxxs.de.
#	Escape character is '^]'.
#	StoneGate firewall (xx.xx.xx.xx) 
#	SG login: 


port = get_kb_item("Services/SG_ClientAuth");
if(!port)port = 2543;
if(!get_port_state(port))exit(0);


r = test_stonegate(port:port);

if (r != 0)
{
	data = "
A StoneGate firewall client authentication  login is displayed.

Here is the banner :

" + r + "


If you see this from the internet or an not administrative
internal network it is probably wrong.";

	security_note(port:port, extra:data);
	exit(0);
}
