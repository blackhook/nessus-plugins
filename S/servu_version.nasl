#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(48434);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"Serv-U Version Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is Serv-U File Server.");
  script_set_attribute(attribute:"description", value:
"Serv-U File Server, an FTP server is listening on this port, and it
is possible to determine its version.

Note that thorough tests may have to be enabled to retrieve the full version.");
  script_set_attribute(attribute:"see_also", value:"https://www.serv-u.com/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:serv-u:serv-u");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2010-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl", "http_version.nasl");
  script_require_ports("Services/ftp", 21);

  exit(0);
}

include('install_func.inc');
include('ftp_func.inc');

var app = "Serv-U";
var version = "unknown";
var kb_data = make_array();
var extra = make_array();

var ftpports = get_kb_list("Services/ftp");
if (isnull(ftpports)) ftpports = make_list(21);

var Ports = make_list();
var port;
var banner;
var i = 0;


## Verify the list of ports are ftp ports
# Check if thorough set, Serv-U banner or unknown port
# Remove any ports which should not be scanned
foreach port (ftpports)
{
  if (!thorough_tests)
  {
     banner = get_kb_item('ftp/banner/'+port);
     if (!pregmatch( pattern:"^.*Serv-U FTP( |-Server | Server )v[ ]*(([0-9a-z-]+\.)+[0-9a-z]+)(.*$|$)",
                     string:banner, icase:TRUE)) continue;
  }
  if (!get_port_state(port)) continue; # Port not responding so we don't need to scan this port
  if (get_kb_item('ftp/'+port+'/backdoor')) continue; # Not a Serv-U
  Ports[i] = port;
  i++;
}

if(empty_or_null(Ports)) audit(AUDIT_NOT_INST, app);

# We may be able to get a build number by looking at the http server banner.
# Grab the version only if it has four parts. We do this before forking at branch().

# www/banner/80=HTTP/1.0 200 OK\r\nServer: Serv-U/15.2.5.5023\
var www_server_version = [];
var www_banner = get_kb_list('www/banner/*');
if(!empty_or_null(www_banner))
{
  foreach(var value in (www_banner))
  {
    var match = pregmatch(
      pattern:"Serv-U\/(\d+(?:\.\d+){3})",
      string:value);

    if(!empty_or_null(match))
    {
      var www_server_version = match[1];
    }
  }
}

var port = branch(Ports);
banner = get_ftp_banner(port:port);

if (!banner) audit(AUDIT_NO_BANNER, port); # No Banner returned can not proceed

var matches = pregmatch(
  pattern:"^.*Serv-U FTP( |-Server | Server )v[ ]*(([0-9a-z-]+\.)+[0-9a-z]+)(.*$|$)",
  string:banner,
  icase:TRUE
);

if (matches)
{
  kb_data['ftp/'+port+'/servu'] = 1;
  extra['Banner'] = kb_data['ftp/'+port+'/servu/banner/source'] = chomp(banner);
  version = kb_data['ftp/'+port+'/servu/banner/version'] = matches[2];
}

if (kb_data['ftp/'+port+'/servu/banner/version'])
{
  kb_data['ftp/'+port+'/servu/version'] = kb_data['ftp/'+port+'/servu/banner/version'];
  kb_data['ftp/'+port+'/servu/source']  = kb_data['ftp/'+port+'/servu/banner/source'];
}

# Default Serv-U banner is Serv-U FTP Server vx.x ready...
# and should be detected without needing CSID command (CSID
# is only needed when admin has changed banner)
#
# For users who want to reduce FTP server logins this CSID command
# adds FTP traffic
#
# This code allows a user to avoid the CSID probe by setting
# supplied logins only and not enabling thorough tests
#
if (!supplied_logins_only || thorough_tests)
{
  # Now try with CSID cmd
  ftp_debug(str:"custom");
  var sock = open_sock_tcp(port);
  if (sock)
  {
    ## Serv-U; Version=15.1.7.162; OS=Linux; OSVer=4.18.0-25-generic; CaseSensitive=1;
    var w = ftp_send_cmd(socket:sock, cmd:"CSID Name=NESSUS;");
    if (preg(pattern:"^220 ", string:w)) w = ftp_recv_line(socket:sock);
    close(sock);

    if (w &&  "Name=Serv-U" >< w)
    {
      kb_data['ftp/'+port+'/servu'] = 1;
      extra['CSID'] = kb_data['ftp/'+port+'/servu/csid/source'] = chomp(w);

      foreach var item (split(w, sep:'; ', keep:FALSE))
      {
        if ('Version=' >< item)
          version = kb_data['ftp/'+port+'/servu/csid/version'] = strstr(item, "Version=") - "Version=";
      }

      # Use CSID if possible (overwrite data from banner)
      if (kb_data['ftp/'+port+'/servu/csid/version'])
      {
        version = kb_data['ftp/'+port+'/servu/version'] = kb_data['ftp/'+port+'/servu/csid/version'];
        kb_data['ftp/'+port+'/servu/source']  = kb_data['ftp/'+port+'/servu/csid/source'];
      }
    }
  }
}

foreach var key (keys(kb_data))
  replace_kb_item(name:key, value:kb_data[key]);

# IF the detected www server version major.minor.patch matches the version detected
# in the FTP banner, use the www version since it also contains the build number.
# This is to address a FP issue in v15.2.3 (CS-44713)
www_server_version_parts = split(www_server_version, sep:'.', keep:FALSE);
if(strcat(version, '.', www_server_version_parts[3]) == www_server_version) version = www_server_version;

if (max_index(keys(kb_data)) > 0)
{
  register_install(
    vendor   : "Serv-U",
    product  : "Serv-U",
    app_name : app,
    version  : version,
    service  : 'ftp',
    port     : port,
    extra    : extra,
    cpe      : "cpe:/a:serv-u:serv-u"
  );

  report_installs(app_name:app, port: port);
 }
else audit(AUDIT_NOT_INST, app);
