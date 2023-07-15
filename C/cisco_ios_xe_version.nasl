##
# (C) Tenable Network Security, Inc.
##

include("compat.inc");

if (description)
{
  script_id(67217);
  script_version("1.41");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/20");

  script_xref(name:"IAVT", value:"0001-T-0552");

  script_name(english:"Cisco IOS XE Version");
  script_summary(english:"Obtains the version of the remote IOS XE.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to read the IOS XE version number of the remote Cisco device.");
  script_set_attribute(attribute:"description", value:
"The remote host is running IOS XE, an operating system for Cisco routers.

Nessus was able to read the IOS XE version number via an SSH connection to the router or via SNMP.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"hardware_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "snmp_sysDesc.nasl", "snmp_cisco_type.nasl", "netconf_detect.nbin");
  script_require_ports("Host/Cisco/show_ver", "SNMP/sysDesc", "Host/netconf/iosxe/system_status");

  exit(0);
}

include('cisco_ios_xe_version_mapping.inc');

function remove_leading_zero(s)
{
  var str, temp;
  var parts = split(s, sep:'.', keep:FALSE);
  foreach var part (parts)
  {
    temp = ereg_replace(pattern:"^0(\d.*)", replace:"\1", string:part);
    if (temp == '') temp = '0';
    if (str) str = str + '.' + temp;
    else str = temp;
  }
  return str;
}

function remove_extra_dot(ver)
{
  var ret = ereg_replace(pattern:"([^\.]*\.[^\.]*\.[^\.]*)(\.)(.*)", replace:"\1\3", string:ver);
  return ret;
}

function standardize_ver_format(ver)
{
  var matches = pregmatch(string:ver, pattern:"([0-9]+)\.([0-9]+)\.([0-9]+)\.([a-zA-Z]+)");
  if (!isnull(matches)) return matches[1] + '.' + matches[2] + '.' + matches[3] + matches[4];

  matches = pregmatch(string:ver, pattern:"([0-9]+)\.([0-9]+)\.([0-9]+)([a-zA-Z]+)");
  if (!isnull(matches)) return ver;

  matches = pregmatch(string:ver, pattern:"([0-9]+)\.([0-9]+)\.([0-9]+)");
  if (!isnull(matches)) return ver;

  exit(1, 'Failed to parse the version number of the remote host.');
}


function test(s, ssh)
{
  if (empty_or_null(s)) return;

  # Cisco IOS Software, IOS-XE Software, Catalyst 4500 L3 Switch Software (cat4500e-UNIVERSALK9-M), Version 03.03.00.SG RELEASE SOFTWARE (fc3)
  # Cisco IOS Software, Catalyst L3 Switch Software (CAT3K_CAA-UNIVERSALK9-M), Version Denali 16.2.1, RELEASE SOFTWARE (fc1)
  # Cisco IOS Software [Denali], Catalyst L3 Switch Software (CAT3K_CAA-UNIVERSALK9-M), Version 16.3.3, RELEASE SOFTWARE (fc3)
  var l = egrep(string:s, pattern:"^.* IOS[ -]XE Software.*, Version [0-9][0-9.a-zA-Z\(\)]+,?");
  if (empty_or_null(l))
    l = egrep(string:s, pattern:"^.*IOS.*Version (Denali|Everest|Fuji) [0-9.]+.*");
  if (empty_or_null(l))
    l = egrep(string:s, pattern:"^.*IOS.*\[(Denali|Everest|Fuji)\].*Version\s+[0-9.]+.*");
  if (empty_or_null(l)) return;

  var v = pregmatch(string:l, pattern:", Version +((Denali|Everest|Fuji)? ?([0-9]+\.[0-9]+[^ ,]+))");
  if (empty_or_null(v)) return;

  var ver = chomp(v[3]);
  if(isnull(v[2]))
  {
    # attempt to convert any IOS versions to IOS-XE versions
    if (cisco_ios_xe_version_map[ver]) ver = cisco_ios_xe_version_map[ver];

    # fix ver...   remove leading 0's
    ver = remove_leading_zero(s:ver);

    # clean up the version by standardizing on a version format
    ver = standardize_ver_format(ver:ver);

    # remove extra dot at the end
    ver = remove_extra_dot(ver:ver);
  }

  set_kb_item(name:'Host/Cisco/IOS-XE/Version', value: ver);

  # Extract model if possible
  # Model is present example :
  # Cisco IOS Software, IOS-XE Software, Catalyst L3 Switch Software (CAT3K_CAA-UNIVERSALK9-M), Version 03.03.01SE RELEASE SOFTWARE (fc1)
  # Model is NOT present example :
  # Cisco IOS Software, IOS-XE Software (X86_64_LINUX_IOSD-UNIVERSAL-M), Version 15.2(4)S, RELEASE SOFTWARE (fc4)
  var banner_pieces = split(l, sep:', ', keep:FALSE);
  var model, matches;

  # Use second line if not enough info
  if (isnull(banner_pieces[2]))
  {
    var model_line = preg(string:s, pattern:"IOS Software,.*Software.*Version [0-9][0-9.a-zA-Z]+.*");
    if (model_line != '')
      banner_pieces = split(model_line, sep:', ', keep:FALSE);
  }

  if ('Cisco IOS Software'    >< banner_pieces[0] || # Allow CSR1000V and like to pass
      'Cisco IOS XE Software' >< banner_pieces[0] ||
      'IOS-XE Software'       >< banner_pieces[1] ||
      'IOS XE Software'       >< banner_pieces[1] )
  {
    if (banner_pieces[2])
    {
      matches = pregmatch(string:banner_pieces[2], pattern:"^(.*) Software \(.*$");
      if (!empty_or_null(matches)) model = matches[1];
    }
    if (!model)
    {
      # We're looking at IOS-XE, but model may be on the second line.
      # IOS-XE virtual appliance is an example; see the two lines :
      # Cisco IOS XE Software, Version 03.10.00.S - Extended Support Release
      # Cisco IOS Software, CSR1000V Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 15.3(3)S, RELEASE SOFTWARE (fc1)
      var m2;
      var l2_pattern = "Cisco IOS Software, (.*) Software \([^)]+\), Version.*";
      var l2 = egrep(string:s, pattern:l2_pattern);
      if (l2 != '') m2 = pregmatch(string:l2, pattern:l2_pattern);
      if (!empty_or_null(m2) && 'IOS-XE' != m2[1] && 'IOS XE' != m2[1]) model = m2[1];
    }

    # In the case of ISR, more detailed model information can be found by looking for
    # cisco...processor as in the cisco_ios_version.nasl detection
    var m3 = pregmatch(string: s, pattern: "cisco ([^\(]+) \([^\)]+\) processor");
    if (!empty_or_null(m3) && toupper(model) == 'ISR')
      model = m3[1];
    else if (!empty_or_null(m3) && strlen(m3[1]) > strlen(model))
      model = m3[1];
    if (!empty_or_null(model))
    {
      set_kb_item(name:'Host/Cisco/IOS-XE/Model', value: model);
    }
  }

  # If Model is still not set, set it equal to device_model
  if (empty_or_null(model))
  {
    var device_model = get_kb_item('Host/Cisco/device_model');
    if (!empty_or_null(device_model))
    {
        model = device_model;
        set_kb_item(name:'Host/Cisco/IOS-XE/Model', value: device_model);
    }
  }

  var image = pregmatch(string: l, pattern: "\((.*)\), *Version");
  if (!empty_or_null(image))
  {
    image = image[1];
    set_kb_item(name:'Host/Cisco/IOS-XE/Image', value: image);
  }

  var type = 'router';

  var source = 'SNMP';
  var port = get_kb_item('SNMP/port');
  if (!port) port = 161;
  if (ssh == TRUE)
  {
   source = 'SSH';
   port = 0;
   var os = 'Cisco IOS XE ' + ver;

   type = get_kb_item('Host/Cisco/device_type');
   if (empty_or_null(type)) type = 'router';

   set_kb_item(name:'Host/OS/CiscoShell', value:os);
   set_kb_item(name:'Host/OS/CiscoShell/Confidence', value:100);
   set_kb_item(name:'Host/OS/CiscoShell/Type', value:type);
  }

  set_kb_item(name:'Host/Cisco/IOS-XE/Port', value: port);
  var report =
    '\n  Source  : ' + source +
    '\n  Version : ' + ver;

  if (!isnull(model)) report += '\n  Model   : ' + model;

  var sdwan = get_kb_item('Host/Cisco/SDWAN/Version');
  if (!empty_or_null(sdwan)) report += '\n  SDWAN Version   : ' + sdwan;

  var operating_mode = get_kb_item('Host/Cisco/IOS-XE/operating_mode');
  if (!empty_or_null(operating_mode)) report += '\n  Operating Mode  : ' + operating_mode;

  report += '\n';
  security_note(port:port, extra:report);

  exit(0);
}

# 1. SSH
showver = get_kb_item('Host/Cisco/show_ver');
test(s: showver, ssh:1);

# 2. SNMP
desc = get_kb_item('SNMP/sysDesc');
test(s: desc);

# 3. NETCONF
if (get_kb_item('Host/netconf/iosxe'))
{
  var system_status = get_kb_item('Host/netconf/iosxe/system_status');

  var device_info = pregmatch(string:system_status, pattern:"<version>(.*)<\/version>.*<product_id>(.*)<\/product_id>");

  if (!empty_or_null(device_info))
  {
    var version = device_info[1];
    var model = device_info[2];

    var port = get_kb_item('Host/netconf/port');
    if (empty_or_null(port)) port = 0;

    set_kb_item(name:'Host/Cisco/IOS-XE/Version', value:version);
    set_kb_item(name:'Host/Cisco/IOS-XE/Model', value:model);
    set_kb_item(name:"Host/Cisco/IOS-XE/Port", value: port);

    if (report_verbosity > 0)
    {
      report =
        '\n  Source  : ' + 'NETCONF' +
        '\n  Version : ' + version;

      if (!isnull(model))
        report += '\n  Model   : ' + model;
      report += '\n';

      security_note(port:port, extra:report);
    }
    else security_note(port);
    exit(0);
  }
}

exit(0, 'The Cisco IOS-XE version is not available (the remote host may not be Cisco IOS-XE).');

