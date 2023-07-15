##
# (C) Tenable Network Security, Inc.
##

include("compat.inc");

if (description)
{
 script_id(55932);
 script_version("1.18");
 script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/07");

  script_xref(name:"IAVT", value:"0001-T-0642");

 script_name(english:"Junos Version Detection");
 script_summary(english:"Obtains the version of the remote Junos device using SSH / SNMP / HTTP");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the operating system version number of the
remote Juniper device.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Junos, an operating system for Juniper
devices. 

It is possible to read the Junos version number by logging into the
device via SSH, using SNMP, or viewing the web interface.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/22");

 script_set_attribute(attribute:"plugin_type", value:"combined");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_set_attribute(attribute:"hardware_inventory", value:"True");
 script_set_attribute(attribute:"os_identification", value:"True");
 script_end_attributes();
 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2011-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Junos Local Security Checks");

 script_dependencies("ssh_get_info.nasl", "snmp_sysDesc.nasl", "os_fingerprint.nasl", "netconf_detect.nbin");
 script_require_ports("Host/Juniper/show_ver", "SNMP/sysDesc", "Host/OS");

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("snmp_func.inc");
include("http.inc");

# 1. SSH

showver = get_kb_item("Host/Juniper/show_ver");

if (showver)
{
  model = pregmatch(string:showver, pattern:'Model: +(.+)');
  junos = pregmatch(string:showver, pattern:'Junos: (.+)');
  port = 0; #SSH port is considered local

  hardware_extensive = get_kb_item("Host/Juniper/show_chassis_hardware_extensive");
  if (!empty_or_null(hardware_extensive))
  {
    he_model = pregmatch(string:hardware_extensive, pattern:'FRU Model Number: +(.+)');
    if (!empty_or_null(he_model) && !empty_or_null(he_model[1]))
      model = he_model;
  }

  # Get approximate Date of Build from Junos build version
  # example: MGD release 16.2R2-S1 built by builder on 2017-08-25 04:07:53 UTC
  if (junos)
  {
    kernel = pregmatch(string:showver, pattern:'(' + junos[1] + ') .+on ([0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) .+');
  }
  # Get Date ond approximate version of Build 
  # example: KERNEL 16.2R2-S1 built by builder on 2019-18-18 12:01:53 UTC
  else
  {
    kernel = pregmatch(string:showver, pattern:'KERNEL ([^ ]+) .+on ([0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9])');
  }

  if (model && kernel)
  {
    set_kb_item(name:"Host/Juniper/model", value:toupper(model[1]));
    set_kb_item(name:"Host/Juniper/kernel", value:kernel[0]);
    set_kb_item(name:"Host/Juniper/JUNOS/Version", value:kernel[1]);
    set_kb_item(name:"Host/Juniper/JUNOS/BuildDate", value:kernel[2]);
    set_kb_item(name:"Host/Juniper/JUNOS/Port", value:port);

    if (report_verbosity > 0)
    {
      report =
        '\n  Junos version : ' + kernel[1] +
        '\n  Build date    : ' + kernel[2] +
        '\n  Model         : ' + toupper(model[1]) +
        '\n  Port          : ' + port +
        '\n  Source        : SSH\n';
      security_note(port:port, extra:report);
    }
    else security_note(port:port);

    exit(0);
  }
}

# 2. SNMP

desc = get_kb_item("SNMP/sysDesc");

if (desc)
{
  junos = pregmatch(string:desc, pattern:"JUNOS ([0-9.]+[^ ]+)");
  build = pregmatch(string:desc, pattern:"Build date: ([0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9])");

  # if the Junos version was obtained via SNMP, try to get the model as well
  if (junos && build)
  {
    community = get_kb_item_or_exit("SNMP/community");
    port = get_kb_item("SNMP/port");
    if(!port) port = 161;

    set_kb_item(name:"Host/Juniper/JUNOS/Version", value:junos[1]);
    set_kb_item(name:"Host/Juniper/JUNOS/BuildDate", value:build[1]);
    set_kb_item(name:"Host/Juniper/JUNOS/Port", value:port);

    if (!get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");
    soc = open_sock_udp(port);
    if (!soc) exit (0, "Failed to open a socket on port "+port+".");
    device = snmp_request(socket:soc, community:community, oid:"1.3.6.1.4.1.2636.3.1.2.0");
    close(soc);

    if (device)
    {
      # e.g. Juniper J2350 Internet Router
      model = pregmatch(string:device, pattern:"^Juniper ([^ ]+)");
      if (model)
        set_kb_item(name:"Host/Juniper/model", value:toupper(model[1]));
      else
        model = 'n/a';
    }

    if (report_verbosity > 0)
    {
      report =
        '\n  Junos version : ' + junos[1] +
        '\n  Build date    : ' + build[1] +
        '\n  Model         : ' + model[1] +
        '\n  Port          : ' + port +
        '\n  Source        : SNMP\n';
      security_note(port:port, extra:report);
    }
    else security_note(port:port);

    exit(0);
  }
}

# 3. NETCONF

if (get_kb_item('Host/netconf/junos'))
{
  var netconf_port = get_kb_item('Host/netconf/port');
  if (netconf_port) set_kb_item(name:'Host/Juniper/JUNOS/Port', value:netconf_port);

  # try and get hardware model and firmware version from 'show versions' output.
  var versions = get_kb_item('Host/netconf/junos/versions');
  if (!empty_or_null(versions))
  {
    var report;
    var version_check = pregmatch(pattern:"JUNOS: ([A-Z0-9\.]+)\n",string:toupper(versions));
    if (!empty_or_null(version_check))
    {
      set_kb_item(name:'Host/Juniper/JUNOS/Version', value:toupper(version_check[1]));
      report += '\n  Junos version : ' + version_check[1];
    }

    var model_check = pregmatch(pattern:'MODEL: ([A-Z]+)',string:toupper(versions));
    if (!empty_or_null(model_check))
    {
      set_kb_item(name:'Host/Juniper/model', value:toupper(model_check[1]));
      report += '\n  Model         : ' + model_check[1];
    }

    if (report_verbosity > 0)
    {
      report +=
        '\n  Port          : ' + netconf_port +
        '\n  Source        : NETCONF\n';
      security_note(port:port, extra:report);
    }
    else security_note(port:port);

    exit(0);
  }
}

# 4. Web (only older versions allow us to view the version w/o authenticating)
os = get_kb_item_or_exit('Host/OS');
if ('junos' >!< tolower(os)) exit(0, 'The host wasn\'t fingerprinted as Junos.');

ports = get_kb_list('Services/www');
if (isnull(ports)) exit(0, 'The "Services/www" KB item is missing.');

foreach port (ports)
{
  res = http_send_recv3(method:'GET', item:'/login', port:port, exit_on_fail:TRUE);
  match = pregmatch(string:res[2], pattern:'<div class="jweb-title uppercase">.* - ([^<]+)</div>');
  if (isnull(match)) continue;
  else model = toupper(match[1]);

  set_kb_item(name:"Host/Juniper/model", value:model);

  res = http_send_recv3(method:'GET', item:'/about', port:port, exit_on_fail:TRUE);
  match = pregmatch(string:res[2], pattern:'Version (.+) *built by [^ ]+ on ([0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9])');
  if (isnull(match)) exit(0, 'Unable to get Junos version from the web interface, authentication may be required.');

  junos = match[1];
  build = match[2];
  set_kb_item(name:"Host/Juniper/JUNOS/Version", value:junos);
  set_kb_item(name:"Host/Juniper/JUNOS/BuildDate", value:build);
  set_kb_item(name:"Host/Juniper/JUNOS/Port", value:port);

  if (report_verbosity > 0)
  {
    report =
      '\n  Junos version : ' + junos +
      '\n  Build date    : ' + build +
      '\n  Model         : ' + model +
      '\n  Port          : ' + port +
      '\n  Source        : HTTP\n';
    security_note(port:port, extra:report);
  }
  else security_note(port:port);

  exit(0);
}

exit(0, "The Junos version is not available.");
