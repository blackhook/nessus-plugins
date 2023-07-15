#TRUSTED af2e6311eaa15559ee363022b441fada4934d84b1f31acbfdc285faffe68f0dcc45f40c494e8f4bd55a8948581ac4b36c0b14362b637dfd5a4d121bfe8be7096c98f5c591299fb38a39665229108261b921bb90b40dcafb7fac5d4ab97bf5e1515248e59d1e50cd35edbfae784431638dbd86177edb6b99269bdce38fb816a5d1c29526e2c2e4efdc09c6989c4a999f559cb169598f6078ac5d30e4664222e96425a91861ff56478bf1aa9cbf6f2e5cce73de27f05baa4f96a8282eb6596d58d21f74b8c2cca5800782bea09ca411c3817c236899adffe4719b34956e123d54d144994ea7fb58f778506b389bc25ff9fb8044b77c2125a748cf5b4336e6be33b21f09a9f1e2f241294ade9a4bc44ecc60b2fae14bbfe56e297578dcb29268cd480a75c11661c067bbe10ffbaa36e7df35619aff0593cd6eb22aa37729abb2d9c30eb85550a484bf0bb2b2d5fcbca10e57ccfb9799717b5053c2ebc5fa2af75f1098f9d6d0735a643df11e35b85466a63006b49c673c9bf549c5179d63542518899aeda6318780f63dc536c56fd3411897f6289d4577eb7d6ca6276e2abe62bdc8e241ba443ea5788500add176a3053f5c41b3d324daffa483dd80abd7cdc34f2d0532f2eaa7d11274d91ce57941f9bf03cfc1d2949b0700bf1dc15cd2604490d57826f9d4fb551ad3fbecbec7784de2d9d9d2015fbf27499ffee6ee0a76b8f99
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70122);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");

  script_xref(name:"IAVT", value:"0001-T-0569");

  script_name(english:"Cisco Wireless LAN Controller (WLC) Version");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the WLC version of the remote Cisco device.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Cisco Wireless LAN Controller (WLC), an operating system for Cisco switches. It is possible
to read the WLC version by connecting to the switch using SSH, SNMP, and/or CAPWAP.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:wireless_lan_controller");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"hardware_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("snmp_sysDesc.nasl", "capwap_detect.nbin", "ssh_cisco_wlc_enumeration.nasl");
  script_require_ports("Host/Cisco/show run-config", "Host/Cisco/show sysinfo", "SNMP/sysDesc", "Services/udp/capwap");

  exit(0);
}

include('snmp_func.inc');
include('install_func.inc');

var app_name = 'Cisco WLC';
var version = NULL;
var cpe = 'cpe:/o:cisco:wireless_lan_controller_software';
var extra = {};
extra['Port'] = '0';

# Check run-config
var run_config = get_kb_item('Host/Cisco/show run-config');
if (run_config && 'Incorrect usage' >!< run_config)
{
  var name_runconfig = pregmatch(pattern:'NAME: "(.*?)"', string:run_config);
  var descr_runconfig = pregmatch(pattern:'DESCR: "(.*?)"', string:run_config);
  var pid_runconfig = pregmatch(pattern:"PID: (.*?),", string:run_config);
  var machine_model_runconfig = pregmatch(pattern:"Machine Model[\.\s]*([^\r\n]+)", string:run_config);

  var product_ver_runconfig = pregmatch(pattern:"Product Version\.+ ([\w-.]*?)[\r\n]", string:run_config);
  var product_name_runconfig = pregmatch(pattern:"Product Name\.+ ([\w\s-_']*?)[\r\n]", string:run_config);
  var build_info_runconfig = pregmatch(pattern:"Build Info\.+ ([\w\s-_']*?)[\r\n]", string:run_config);

  if (machine_model_runconfig) extra['Model'] = machine_model_runconfig[1];
  else if (pid_runconfig) extra['Model'] = pid_runconfig[1];
  if (name_runconfig) extra['Name'] = name_runconfig[1];
  if (descr_runconfig) extra['Description'] = descr_runconfig[1];
  if (product_ver_runconfig) version = product_ver_runconfig[1];
  if (product_name_runconfig) extra['Product Name'] = product_name_runconfig[1];
  if (build_info_runconfig) extra['Build Info'] = build_info_runconfig[1];
}

var sysinfo = get_kb_item('Host/Cisco/show sysinfo');
if (sysinfo && 'Incorrect usage' >!< sysinfo)
{
  var version_sysinfo = pregmatch(string:sysinfo, pattern:"Product Version\.+ ([\w-.]*?)[\r\n]");
  var product_name_sysinfo = pregmatch(pattern:"Product Name\.+ ([\w-.]*?)[\r\n]", string:sysinfo);
  var build_info_sysinfo = pregmatch(pattern:"Build Info\.+ ([\w\s-_']*?)[\r\n]", string:sysinfo);

  if (!version && version_sysinfo) version = version_sysinfo[1];
  if (!extra['Product Name'] && product_name_sysinfo) extra['Product Name'] = product_name_sysinfo[1];
  if (!extra['Build Info'] && build_info_sysinfo) extra['Build Info'] = build_info_sysinfo[1];
}

var inventory = get_kb_item('Host/Cisco/show inventory');
if (inventory && 'Incorrect usage' >!< inventory)
{
  var name_inventory = pregmatch(pattern:'NAME: "(.*?)"', string:inventory);
  var descr_inventory = pregmatch(pattern:'DESCR: "(.*?)"', string:inventory);
  var machine_model_inventory = pregmatch(pattern:"Machine Model[\.\s]*([^\r\n]+)", string:inventory);
  var pid_inventory = pregmatch(pattern:"PID: (.*?),", string:inventory);
  if (!extra['Name'] && name_inventory) extra['Name'] = name_inventory[1];
  if (!extra['Description'] && descr_inventory) extra['Description'] = descr_inventory[1];
  if (!extra['Model'] && machine_model_inventory) extra['Model'] = machine_model_inventory[1];
  if (!extra['Model'] && pid_inventory) extra['Model'] = pid_inventory[1];
}

if (version)
{
  extra['Protocol'] = 'TCP';
  extra['Source'] = 'SSH';
}

# SNMP
var snmp_sysDesc = get_kb_item('SNMP/sysDesc');
var community = get_kb_item('SNMP/community');
if (snmp_sysDesc && community)
{
  var snmp_port = get_kb_item('SNMP/port');
  if(!snmp_port) snmp_port = 161;
  if (get_udp_port_state(snmp_port))
  {
    var snmp_soc = open_sock_udp(snmp_port);
    if (snmp_soc)
    {
      # Sanity Check. are we looking at a WLC device?
      var snmp_wlc = snmp_request(socket:snmp_soc, community:community, oid:'1.3.6.1.2.1.1.1.0');
      if (!isnull(snmp_wlc) && snmp_wlc =~ 'Cisco Controller')
      {
        # get version
        var snmp_version = snmp_request(socket:snmp_soc, community:community, oid:'1.3.6.1.2.1.47.1.1.1.1.10.1');
        if (!version && snmp_version)
        {
          version = snmp_version;
          extra['Port'] = snmp_port;
          extra['Source'] = 'SNMP';
          extra['Protocol'] = 'UDP';
        }
        # Get hardware model
        snmp_model = snmp_request(socket:snmp_soc, community:community, oid:'1.3.6.1.2.1.47.1.1.1.1.13.1');
        if (!extra['Model'] && snmp_model) extra['Model'] = snmp_model;
      }
    }
  }
}

# CAPWAP 
var capwap_port = get_kb_item('Services/udp/capwap');
if (capwap_port)
{
  var vid = 0x409600; # Cisco WLC uses this
  var type = 1;
  var capwap_ver = get_kb_item('CAPWAP/ac_info/' + vid + '/' + type);
  if (!version && capwap_ver)
  {
    capwap_ver = hex2raw(s:capwap_ver);
    if(capwap_ver && strlen(capwap_ver) == 4)
    {
      version = ord(capwap_ver[0]) + '.' + ord(capwap_ver[1]) + '.' + ord(capwap_ver[2]) + '.' + ord(capwap_ver[3]);
      extra['Port'] = capwap_port;
      extra['Source'] = 'CAPWAP';
      extra['Protocol'] = 'UDP';
    }
  }
}

if (!version || empty_or_null(version)) audit(AUDIT_UNKNOWN_APP_VER, app_name);

if (!extra['Model']) extra['Model'] = 'Unknown';
set_kb_item(name:'Host/Cisco/WLC/Version', value:version);
set_kb_item(name:'Host/Cisco/WLC/Model', value:extra['Model']);
set_kb_item(name:'Host/Cisco/WLC/Port', value:extra['Port']);

if (extra['Name']) set_kb_item(name:'Host/Cisco/WLC/Name', value:extra['Name']);
if (extra['Description']) set_kb_item(name:'Host/Cisco/WLC/Description', value:extra['Description']);
if (extra['Product Name']) set_kb_item(name:'Host/Cisco/WLC/Product Name', value:extra['Product Name']);
if (extra['Build Info']) set_kb_item(name:'Host/Cisco/WLC/Build Info', value:extra['Build Info']);
if (extra['Protocol']) set_kb_item(name:'Host/Cisco/WLC/Protocol', value:extra['Protocol']);
if (extra['Source']) set_kb_item(name:'Host/Cisco/WLC/Source', value:extra['Source']);

register_install(
  app_name  : app_name,
  vendor : 'Cisco',
  product : 'Wireless LAN Controller',
  path      : "/",
  version   : version,
  extra     : extra,
  cpe       : cpe
);

report_installs(app_name:app_name);
