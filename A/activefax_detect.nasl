#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53322);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/22");

  script_name(english:"ActiveFax Server Detection");
  script_summary(english:"Look for ActiveFax Server FTP or Telnet banners");

  script_set_attribute(attribute:"synopsis", value:
"A fax server is running on this host." );
  script_set_attribute(attribute:"description", value:
"ActiveFax Server is running on this host.  " );
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_attribute(attribute:"see_also", value: "http://www.actfax.com/");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/07");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:actfax:active_fax_server");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Service detection");
  script_dependencies("telnetserver_detect_type_nd_version.nasl", "ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 21, "Services/ftp", 23);
  exit (0);

}

include("global_settings.inc");
include("misc_func.inc");
include("telnet_func.inc");
include("ftp_func.inc");

function test_telnet(port)
{
  local_var	s, b, ver, v;

  b = get_telnet_banner(port: port);
  if (isnull(b)) return NULL;
  if ("Welcome at ActiveFax Server" >!< b) return NULL;

  s = open_sock_tcp(port);
  if (!s) return NULL;
  b = telnet_negotiate(socket: s, pattern: '^\\[Q\\] Quit');
  send(socket: s, data: '1\n');
  b = recv(socket: s, length: 1024);
  v = eregmatch(string: b, pattern: "ActiveFax Server Version ([0-9.]+ \(Build [0-9]+\))");
  if (! isnull(v)) ver = v[1];
  send(socket: s, data: '\n');
  recv(socket: s, length: 1024);
  send(socket: s, data: 'Q\n');
  close(s);
  return ver;
}

function test_ftp(port)
{
  local_var	b, v, ver;

  b = get_ftp_banner(port: port);
  if (isnull(b)) return NULL;
  v = eregmatch(string: b, pattern: "^[0-9]{3} ActiveFax Version ([0-9.]+ \(Build [0-9]+\))");
  if (! isnull(v)) return v[1];
  return NULL;
}

l = make_service_list("Services/telnet", 23);
foreach p (l)
  if (get_tcp_port_state(p))
  {
    ver = test_telnet(port: p);
    if (ver)
    {
      security_note(port: p, extra: '\nThis is the Telnet interface for ActiveFax Server '+ ver +'.\n');
      set_kb_item(name: 'ActiveFax/Server', value: ver);
    }
  }



l = make_service_list("Services/ftp", 21);
foreach p (l)
  if (get_tcp_port_state(p))
  {
    ver = test_ftp(port: p);
    if (ver)
    {
      security_note(port: p, extra: '\nThis is the FTP interface for ActiveFax Server '+ ver +'.\n');
      set_kb_item(name: 'ActiveFax/Server', value: ver);
    }
  }
