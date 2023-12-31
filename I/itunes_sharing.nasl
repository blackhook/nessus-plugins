#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20217);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");

  script_name(english:"Apple iTunes Music Sharing Enabled");
  script_summary(english:"Checks whether music sharing is enabled in iTunes.");

  script_set_attribute(attribute:"synopsis", value:
"Apple iTunes is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"Apple iTunes, a popular media player, is running on the remote host.
Additionally, it is configured to stream music between hosts. This
functionality may not be in compliance with your corporate security
policy regarding file sharing or network usage.");
  script_set_attribute(attribute:"solution", value:
"Disable song sharing or limit access to the port.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");
  script_copyright(english:"This script is Copyright (C) 2005-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 3689);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("install_func.inc");


app = 'iTunes DAAP';
port = get_kb_item("Services/www");
if (!port) port = 3689;
if (!get_tcp_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

# Look for the iTunes banner.
banner = get_http_banner(port:port, broken:TRUE, exit_on_fail:TRUE);
if ("DAAP-Server: iTunes/" >< banner)
{
  path = "daap://" + get_host_ip() + ":" + port+ "/";
  w = http_send_recv3(method:"GET",item:path+ "server-info", port:port, exit_on_fail:TRUE);
  if (
    w[0] =~ "^HTTP/1.1 200 OK" ||
    (
      w[0] =~ "^HTTP/1.1 501 Not Implemented" &&
      "application/x-dmap-tagged" >< w[1]
    )
  )
  {
    # Isolate DAAP server string
    daap = strstr(banner, "DAAP-Server: iTunes/");
    daap = daap - strstr(daap, '\r\n');

    type = 'Mac OSX';

    # Windows Check
    if ("(Windows)" >< banner) type = 'Windows';

    # AppleTV Check
    appletv_regex = "^DAAP-Server: iTunes/[0-9][0-9.]+[^0-9.]+[0-9]+ \((Mac )?OS X\)";
    if (pgrep(pattern:appletv_regex, string:banner))
    {
       type = 'AppleTV';

       # Get AppleTV Version
       match = pregmatch(pattern:"^DAAP-Server: iTunes/([0-9][0-9.]+[^0-9.]+[0-9]+)", string:daap);
       if(empty_or_null(match)) audit(AUDIT_UNKNOWN_APP_VER, app);
       version = match[1];
    }
    # Get Version for Regular iTunes
    else
    {
      match = pregmatch(pattern:"^DAAP-Server: iTunes/([0-9][0-9.]+)", string:daap);
      if(empty_or_null(match)) audit(AUDIT_UNKNOWN_APP_VER, app);
      version = match[1];
    }

    set_kb_item(name:"iTunes/sharing", value:TRUE);
    set_kb_item(name:"iTunes/" + port + "/enabled", value:TRUE);
    set_kb_item(name:"iTunes/" + port + "/source", value:daap);
    set_kb_item(name:"iTunes/" + port + "/version", value:version);
    set_kb_item(name:"iTunes/" + port + "/type", value:type);

    extra.Source = daap;
    extra.Type = type;
    register_install(
      app_name:app,
      vendor : 'Apple',
      product : 'iTunes',
      path:'/',
      version:version,
      port:port,
      extra:extra,
      webapp:TRUE,
      cpe:"cpe:/a:apple:itunes");

    report_installs(app_name:app, port:port);
  }
}
else audit(AUDIT_NOT_LISTEN, "iTunes Music Sharing", port);
