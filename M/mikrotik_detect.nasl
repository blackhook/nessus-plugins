#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30212);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");
  script_xref(name:"IAVT", value:"0001-T-0671");

  script_name(english:"MikroTik RouterOS Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is a router.");
  script_set_attribute(attribute:"description", value:
"According to one of its service banners, the remote host is running
MikroTik RouterOS, a specialized Linux-based operating system that
allows Intel-class PCs to act as a network router or access point.");
  script_set_attribute(attribute:"see_also", value:"https://mikrotik.com/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mikrotik:routeros");
  script_set_attribute(attribute:"hardware_inventory", value:"true");
  script_set_attribute(attribute:"os_identification", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl", "doublecheck_std_services.nasl", "mikrotik_mndp_detect.nbin", "mikrotik_winbox_detect.nasl");
  script_require_ports("Services/ftp", 21, "Services/ssh", 22, "Services/telnet", 23, "Services/www", 80, "Services/unknown", 8291);

  exit(0);
}

include("global_settings.inc");
include("ftp_func.inc");
include("misc_func.inc");
include("http.inc");
include("telnet_func.inc");


# Use a service banner to fingerprint it as running RouterOS,
# and get its version if possible.
service = NULL;
ver = NULL;

##
# Reports that Nessus that the remote host is running
# RouterOS and then exits the script
##
function report_and_exit()
{
  local_var report = '\n' + 'According to its ' + service +
    ' service, the remote host is running MikroTik\nRouterOS';

  if (!isnull(ver))
  {
    report += ' version ' + ver;
    report += '.';
    set_kb_item(name:"MikroTik/RouterOS/Version", value:ver);
  }
  security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
  exit(0);
}

# - HTTP.
# Moved this check up to the front because we want to
# always flag the HTTP server as embedded if we can.
ports = get_kb_list("Services/www");
if (isnull(ports)) ports = make_list(80);
foreach port (ports)
{
  if (get_port_state(port))
  {
    res = http_get_cache(item:"/", port:port, exit_on_fail:FALSE);
    if (res && "mikrotik" >< res)
    {
      pat = "<h1>RouterOS v([0-9][0-9.]+)<";
      matches = pgrep(pattern:pat, string:res);

      if (!matches)
      {
        pat = ">mikrotik routeros (.+) configuration page<";
        matches = pgrep(pattern:pat, string:res);
      }

      if (matches)
      {
        set_kb_item(name:"Services/www/"+port+"/embedded", value:TRUE);

        foreach match (split(matches))
        {
          match = chomp(match);
          item = pregmatch(pattern:pat, string:match);
          if (!isnull(item))
          {
            ver = item[1];
            service = "HTTP";
            break;
          }
        }
      }
    }
    if (service) report_and_exit();
  }
}

# - MNDP.
ver = get_kb_item("MikroTik/MNDP/7");
if (!empty_or_null(ver))
{
  service = "MNDP";
  report_and_exit();
}

# - WINBOX
port = get_kb_item("Services/mikrotik_winbox");
if (!empty_or_null(port))
{
  ver = get_kb_item("MikroTik/Winbox/" + port + "/Version");
  if (!empty_or_null(ver))
  {
    if (ver =~ "^[0-9][0-9.]+$") service = "WINBOX";
    else ver = NULL;
    if (service) report_and_exit();
  }
}

# - FTP.
ports = get_kb_list("Services/ftp");
if (isnull(ports)) ports = make_list(21);
foreach port (ports)
{
  if (get_port_state(port))
  {
    banner = get_ftp_banner(port:port);
    if (banner && "MikroTik FTP" >< banner)
    {
      pat = "^[0-9]{3} .+ FTP server \(MikroTik ([^\)rc]+[0-9.]+?).*?\) ready";
      matches = pgrep(pattern:pat, string:banner);
      if (matches)
      {
        foreach match (split(matches))
        {
          match = chomp(match);
          item = pregmatch(pattern:pat, string:match);
          if (!isnull(item))
          {
            ver = item[1];
            service = "FTP";
            break;
          }
        }
      }
    }
    if (service) report_and_exit();
  }
}

# - Telnet.
ports = get_kb_list("Services/telnet");
if (isnull(ports)) ports = make_list(23);
foreach port (ports)
{
  if (get_port_state(port))
  {
    banner = get_telnet_banner(port:port);
    if (banner && "MikroTik v" >< banner)
    {
      pat = "^MikroTik v([0-9].+)$";
      matches = pgrep(pattern:pat, string:banner);
      if (matches)
      {
        foreach match (split(matches))
        {
          match = chomp(match);
          item = pregmatch(pattern:pat, string:match);
          if (!isnull(item))
          {
            ver = item[1];
            service = "Telnet";
            break;
          }
        }
      }
    }
    if (service) report_and_exit();
  }
}

# - SSH.
#
# nb: keep this towards the end as it doesn't offer up the version of RouterOS.
ports = get_kb_list("Services/ssh");
if (isnull(ports)) ports = make_list(22);
foreach port (ports)
{
  if (get_port_state(port))
  {
    soc = open_sock_tcp(port);
    if (soc)
    {
      banner = recv_line(socket:soc, length:4096);
      close(soc);

      if (
        banner &&
        preg(pattern:"^SSH-.+(_Mikrotik_v|-ROSSSH)", string:banner)
      ) service = "SSH";

      if (service) report_and_exit();
    }
  }
}
