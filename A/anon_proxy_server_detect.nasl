#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#


include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(29703);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Anon Proxy Server Software Detection");

  script_set_attribute(attribute:"synopsis", value:
"Anon Proxy Server is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote service is a proxy server named Anon Proxy Server, which
can operate either as a normal HTTP / HTTPS / Socks proxy or a P2P
anonymous proxy.");
  script_set_attribute(attribute:"see_also", value:"http://anonproxyserver.sourceforge.net/");
  script_set_attribute(attribute:"solution", value:
"Make sure use of this program is in accordance with your corporate
security policy.  And limit incoming traffic to this port if desired.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:anon_proxy_server:anon_proxy_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl", "httpver.nasl");
  script_require_ports("Services/www", 80, "Services/http_proxy", 8080, 8082);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# Get a list of possible ports.
ports = add_port_in_list(list:get_kb_list("Services/http_proxy"), port:8080);
ports = add_port_in_list(list:ports, port:8082);
# nb: currently find_service.nes flags this as a web server.
www_servers = get_kb_list("Services/www");
if (!isnull(www_servers))
{
  foreach port (www_servers)
    ports = add_port_in_list(list:ports, port:port);
}


# Iterate over each port.
foreach port (ports)
{
  if (get_port_state(port))
  {
    # Look for Anon-Proxy response header in the banner.
    banner = get_http_banner(port:port);
    if (banner && "Anon-Proxy: message" >< banner) 
    {
      register_service(port:port, proto:"http_proxy");
      security_note(port);
    }
  }
}
