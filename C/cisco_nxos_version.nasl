#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(66696);
 script_version("1.20");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/15");

  script_xref(name:"IAVT", value:"0001-T-0555");

 script_name(english:"Cisco NX-OS Version");

 script_set_attribute(attribute:"synopsis", value:"It is possible to obtain the NX-OS version of the remote Cisco device.");
 script_set_attribute(attribute:"description", value:
"The remote host is running NX-OS, an operating system for Cisco
switches.

It is possible to read the NX-OS version and Model either through SNMP
or by connecting to the switch using SSH.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/30");

 script_set_attribute(attribute:"plugin_type", value:"combined");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_set_attribute(attribute:"hardware_inventory", value:"True");
 script_set_attribute(attribute:"os_identification", value:"True");
 script_end_attributes();
 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"CISCO");

 script_dependencies("ssh_get_info.nasl", "snmp_sysDesc.nasl", "snmp_cisco_type.nasl");
 script_require_ports("Host/Cisco/show_ver", "SNMP/sysDesc", "Host/aci/system/firmware/summary", "Host/Cisco/apic/show_version");
 exit(0);
}

include("snmp_func.inc");
include("ssh_lib.inc");

##
# Saves the provided NXOS version number in the KB, generates plugin output,
# and exits.  If a model number is provided it is also saved in
# the KB and reported, but a model number is not required.
#
# @param ver NXOS version number
# @param device NXOS device type
# @param model NXOS model number
# @param source service used to obtain the version
# @param port Port used in detection (0 for SSH)
# @param proto Protocol used in detection (udp or tcp)
#
# @return NULL if 'ver' is NULL,
#         otherwise this function exits before it returns
##
function report_and_exit(ver, device, model, source, port, proto)
{
  local_var report, os;

  if (isnull(proto)) proto = 'tcp';

  set_kb_item(name:"Host/Cisco/NX-OS/Device", value:device);

  if (!isnull(model))
    set_kb_item(name:"Host/Cisco/NX-OS/Model", value:model);

  set_kb_item(name:"Host/Cisco/NX-OS/Version", value:ver);
  set_kb_item(name:"Host/Cisco/NX-OS/Port", value:port);
  set_kb_item(name:"Host/Cisco/NX-OS/Protocol", value:proto);

  replace_kb_item(name:"Host/Cisco/NX-OS", value:TRUE);

  if ( source == "SSH" )
  {
   os = "CISCO NX-OS " + ver;
   set_kb_item(name:"Host/OS/CiscoShell", value:os);
   set_kb_item(name:"Host/OS/CiscoShell/Confidence", value:100);
   set_kb_item(name:"Host/OS/CiscoShell/Type", value:"switch");
  }

  report =
    '\n  Source  : ' + source +
    '\n  Version : ' + ver;
  if (!isnull(device))
    report += '\n  Device  : ' + device;
  if (!isnull(model))
    report += '\n  Model   : ' + model;
  if (port)
    report += '\n  Port    : ' + port;

  report += '\n';

  security_report_v4(severity:SECURITY_NOTE, port:port, proto:proto, extra:report);

  exit(0);
}

var version = NULL;
var device = NULL;
var model = NULL;

var ips_ssh, ssh_port, banner, pat, ips_snmp, community, port, soc, txt, ips_aci, model_kb, ips_apic, failed_methods;

# 1. SSH
ips_ssh = get_kb_item("Host/Cisco/show_ver");
if (ips_ssh)
{
  if ("Cisco Nexus Operating System (NX-OS) Software" >< ips_ssh)
  {
    version = pregmatch(string:ips_ssh, pattern:"NXOS:\s+version\s+([0-9a-zA-Z\.\(\)]+)[^\s\r\n]*", icase:TRUE);
    if (isnull(version))
      version = pregmatch(string:ips_ssh, pattern:"[Ss]ystem:?\s+[Vv]ersion:?\s+([0-9a-zA-Z\.\(\)]+)[^\s\r\n]*");

    if (!isnull(version))
    {
      # Check if it's a UCS device
      # this can be expanded when we know more about Cisco UCS products
      ssh_port = get_service(svc:'ssh', default:22);
      banner = get_kb_item('SSH/textbanner/'+ssh_port);
      # e.g. textbanner = Cisco UCS 6200 Series Fabric Interconnect\n 
      if (!isnull(banner))
      {
        banner = chomp(banner);
        pat = "^Cisco UCS (\S+ Series) Fabric Interconnect$";
        model = pregmatch(string:banner, pattern:pat, icase:TRUE);
        if (!isnull(model)) device = 'Cisco UCS Fabric Interconnect';
      }

      if (isnull(model))
      {
        if ('MDS' >< ips_ssh)
        {
          device = 'MDS';

          model = pregmatch(string:ips_ssh, pattern:"MDS\s*\d+\s+[cC]([^\r\n\s]+)[^\r\n]*\s+Chassis");
          if (isnull(model))
            model = pregmatch(string:ips_ssh, pattern:"MDS\s*([^\r\n\s]+)[^\r\n]*\s+Chassis");
        }
        else
        {
          device = 'Nexus';

          model = pregmatch(string:ips_ssh, pattern:"[Nn]exus\s*\d+\s+[cC]([^\r\n\s]+)[^\r\n]*\s+[Cc]hassis");
          if (isnull(model))
            model = pregmatch(string:ips_ssh, pattern:"[Nn]exus\s*([^\r\n\s]+)[^\r\n]*\s+[Cc]hassis");
          if (isnull(model))
          model = pregmatch(string:ips_ssh, pattern:"Hardware\r?\n\s*[Cc]isco (?:[Nn]exus )?\s*([^\r\n\s]+)\s+([Cc]hassis|\(.[Ss]upervisor.\))");
        }
      }

      if (!isnull(model))
        model = model[1];

      report_and_exit(ver:version[1], device:device,  model:model, source:'SSH', port:0);

    }
  }
}

# 2. SNMP
ips_snmp = get_kb_item("SNMP/sysDesc");
if (ips_snmp)
{
  community = get_kb_item("SNMP/community");
  if ( (community) && (!model) )
  {
    port = get_kb_item("SNMP/port");
    if(!port)port = 161;
    if (! get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

    soc = open_sock_udp(port);
    if (soc)
    {
      txt = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.1.1.0");
      if ( (txt) && ('NX-OS' >< txt) )
      {
        # get version
        txt = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.47.1.1.1.1.9.22");
        if (txt) version = txt;

        # get model
        txt = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.47.1.1.1.1.2.149");
        if (txt && 'MDS' >< txt)
        {
          device = 'MDS';

          model = pregmatch(string:txt, pattern:"MDS\s*([^\r\n\s]+)[^\r\n]*\s+Chassis");
        }
        if (txt && 'Nexus' >< txt)
        {
          device = 'Nexus';

          model = pregmatch(string:txt, pattern:"Nexus\s*([^\r\n\s]+)[^\r\n]*\s+Chassis");

        }
      }
    }
  }

  if (!isnull(model))
    model = model[1];

  if (!isnull(version))
    report_and_exit(ver:version, device:device, model:model, source:'SNMP', port:port, proto:'udp');
}

# 3. SSH (Nexus 9xxx Switches may support "ACI" (bash shell)
#          which also allows us to obtain version information)
ips_aci = get_kb_item("Host/aci/system/firmware/summary");
if (ips_aci)
{
  # Same expected format as with SSH above
  version = pregmatch(string:ips_aci, pattern:"[Dd]escription\s+:\s[Vv]ersion\s([0-9a-zA-Z\.\(\)]+)\s");

  if (!empty_or_null(version) && !empty_or_null(version[1]))
  {
    version = version[1];
    device = 'Nexus';

    model_kb = get_kb_item("Host/aci/system/chassis/summary");
    model = pregmatch(string:model_kb, pattern:"[Nn]exus\s*\d+\s+[cC]([^\s]+)[^\r\n]*\s+[Cc]hassis");
    if (isnull(model))
    {
      model = pregmatch(string:model_kb, pattern:"[Nn]exus\s*([^\s]+)[^\r\n]*\s+[Cc]hassis");
    }
    if (!empty_or_null(model) && !empty_or_null(model[1]))
      model = model[1];

    report_and_exit(ver:version, device:device,  model:model, source:'SSH', port:0);
  }
}

# 4. SSH (Nexus APIC Controller may support "ACI" (bash shell)
#          which also allows us to obtain version information)
ips_apic = get_kb_item("Host/Cisco/apic/show_version");
if (ips_apic)
{
  version = pregmatch(string:ips_apic, pattern:"\s([\d]+\.[\d]+\(.+\))");
  if (!empty_or_null(version) && !empty_or_null(version[1]))
  {
    version = version[1];
    device = 'Cisco Application Policy Infrastructure Controller';
    model = 'Cisco APIC';

    report_and_exit(ver:version, device:device, model:model, source:'SSH', port:0);
  }
}


failed_methods = make_list();
if (ips_ssh)
  failed_methods = make_list(failed_methods, 'SSH');
if (ips_snmp)
  failed_methods = make_list(failed_methods, 'SNMP');
if (ips_aci)
  failed_methods = make_list(failed_methods, 'SSH (ACI feature)');
if (ips_apic)
  failed_methods = make_list(failed_methods, 'SSH (ACI on APIC)');

if (max_index(failed_methods) > 0)
  exit(1, 'Unable to determine Cisco NX-OS version number obtained via ' + join(failed_methods, sep:'/') + '.');
else
  exit(0, 'The Cisco NX-OS version is not available (the remote host may not be Cisco NXOS).');
