#
# Script Written By Ferdy Riphagen 
# <f[dot]riphagen[at]nsec[dot]nl>
#
# Script distributed under the GNU GPLv2 License.
#

# Changes by Tenable :
#  - Improved version extraction
#  - Report layout
#  - Fixed SSL detection
#  - Added cpe and updated copyright

include("compat.inc");

if (description) {
 script_id(20225);
 script_version("1.12");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/12");

 script_name(english:"Kerio WinRoute Firewall HTTP/HTTPS Management Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a firewall application." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running the Kerio WinRoute Firewall
application.  It is possible to access the HTTP or HTTPS management
interface on the host." );
 script_set_attribute(attribute:"solution", value:
"If the service is not needed, disable HTTP and/or HTTPS management, 
or filter incomming requests to the ports from untrusted sources." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/11/18");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:kerio:winroute_firewall");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_end_attributes();

 script_summary(english:"Check if Kerio WinRoute Firewall HTTP/HTTPS management is enabled");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Firewalls");
 script_copyright(english:"This script is Copyright (C) 2005-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 4080, 4081);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:4080, embedded:TRUE);
if (!get_port_state(port)) get_http_port(default:4081, embedded:TRUE);
if (!get_port_state(port)) exit(0);


res = http_get_cache_ka(item: "/", port: port);
if (!res) exit(0);
if ("Kerio WinRoute Firewall" >< res &&
      ( line = egrep(pattern: "Kerio WinRoute Firewall [0-9.]+", string: res)))
{
  # Check and build the version.
  version = ereg_replace(pattern:".*Kerio WinRoute Firewall ([0-9.]+).*", string:line, replace:"\1");
  if (version == line ) version = NULL;

  if ( version != NULL )
  {
    report = 
"The version of the application is :
" +version;
    security_warning(port: port, extra: report);
  }
  else
    security_warning(port: port);

  if ( version != NULL ) set_kb_item(name:"Services/www/" + port + "/kerio_wrf", value:version);
  exit(0);
}
