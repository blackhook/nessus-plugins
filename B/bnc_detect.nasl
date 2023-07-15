#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(34236);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"BNC Detection");

  script_set_attribute(attribute:"synopsis", value:
"An IRC bouncer is running on this port.");
  script_set_attribute(attribute:"description", value:
"BNC, an IRC bouncer from The BNC Project, is running on this port.  It
proxies communications between IRC clients and servers.  This may be
done to allow clients without direct network access to connect to
servers or to hide client addresses. 

Legimate use of such proxies is rare.  They are often installed by
attackers in order to avoid detection while controlling a 'botnet'.");
  script_set_attribute(attribute:"see_also", value:"http://www.gotbnc.com/");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Bouncer_(networking)");
  script_set_attribute(attribute:"solution", value:
"Make sure that use of this software is in agreement with your
organization's security policy.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bnc:bnc");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl", "find_service2.nasl");
  script_require_ports(6666, 6667, 9000, "Services/unknown");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery"))
  ports_l = make_list(6666, 6667, 9000, "Services/unknown");
else
  ports_l = make_list(6666, 6667, 9000);

user = rand_str();

foreach port (ports_l)
 if (get_port_state(port) && service_is_unknown(port: port))
 {
   soc = open_sock_tcp(port);
   if (soc)
   {
     send(socket: soc, data: strcat('NICK ', user, '\n'));
     r = recv(socket: soc, length: 1024);
     close(soc);
     if (r == 'NOTICE AUTH :You need to say /quote PASS <password>\n')
     {
       security_note(port);
       register_service(port: port, proto: "irc-bnc");
     }
   }
 }
