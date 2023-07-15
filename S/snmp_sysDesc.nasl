#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10800);
 script_version("1.31");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/18");
 
 script_name(english:"SNMP Query System Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The System Information of the remote host can be obtained via SNMP." );
 script_set_attribute(attribute:"description", value:
"It is possible to obtain the system information about the remote
host by sending SNMP requests with the OID 1.3.6.1.2.1.1.1.

An attacker may use this information to gain more knowledge about
the target host." );
 script_set_attribute(attribute:"solution", value:
"Disable the SNMP service on the remote host if you do not use it,
or filter incoming UDP packets going to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/11/06");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Enumerates system info via SNMP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"SNMP");
 script_dependencies("snmp_settings.nasl", "find_service2.nasl");
 script_require_keys("SNMP/community");
 exit(0);
}


include ("snmp_func.inc");

var community = get_kb_item_or_exit("SNMP/community");
var port = get_kb_item("SNMP/port");


#list of oids and their extra information
var oid_extra_info = {
  #moxa (verified with pcap)
  '1.3.6.1.4.1.8691'      : {'Model'   : "1.3.6.1.4.1.8691.7.9.1.2.0",
                             'Version' : "1.3.6.1.4.1.8691.7.9.1.4.0"},
  #Hirschmann
  '1.3.6.1.4.1.248'       : {'hmSysProduct'   : '1.3.6.1.4.1.248.14.1.1.1',
                             'hmSysVersion' : '1.3.6.1.4.1.248.14.1.1.2'},
  #Wago (verified with pcap)
  '1.3.6.1.4.1.13576'     : {'wioFirmwareIndex'   : '1.3.6.1.4.1.13576.10.1.10.1',
                             'wioHardwareIndex'   : '1.3.6.1.4.1.13576.10.1.10.2',
                             'wioFwlIndex'        : '1.3.6.1.4.1.13576.10.1.10.3',
                             'wioFirmwareVersion' : '1.3.6.1.4.1.13576.10.1.10.4'},

  # Scalance
  '1.3.6.1.4.1.4329'      : {'automationOrderNumber'   : '1.3.6.1.4.1.4329.6.3.2.1.1.2.0',
                             'automationSwRevision' : '1.3.6.1.4.1.4329.6.3.2.1.1.5.0'},

  # Ruckus
  '1.3.6.1.4.1.25053'     : {'ruckusUnleashedSystemModel'   : '1.3.6.1.4.1.25053.1.15.1.1.1.1.9',
                             'ruckusUnleashedSystemVersion'   : '1.3.6.1.4.1.25053.1.15.1.1.1.1.18'},

  # SonicWall
  '1.3.6.1.4.1.8741'      : {'snwlSysModel'	          : '1.3.6.1.4.1.8741.2.1.1.1',
                             'snwlSysFirmwareVersion' : '1.3.6.1.4.1.8741.2.1.1.3'}
};

#hirschmann gives you an integer for its product and has a table that connects integers to device models
var hirschmann_product_lookup = {
    1 : 'rs2-tx-tx',                 2 : 'rs2-fx-fx',                   3 : 'rs2-fxsm-fxsm',             10 : 'mach3002',
   11 : 'mach3005',                 12 : 'mach3001',                   20 : 'ms2108-2',                  21 : 'ms3124-4',
  100 : 'rs2-16m',                 101 : 'rs2-15m',                   102 : 'rs2-14m',                  110 : 'rs2-16m-1mm-sc',
  111 : 'rs2-16m-1sm-sc',          112 : 'rs2-16m-1lh-sc',            120 : 'rs2-15m-1mm-sc',           121 : 'rs2-15m-1sm-sc',
  122 : 'rs2-15m-1lh-sc',          130 : 'rs2-16m-2mm-sc',            131 : 'rs2-16m-2sm-sc',           132 : 'rs2-16m-2lh-sc',
  140 : 'rs2-16m-1mm-sc-1sm-sc',   141 : 'rs2-16m-1mm-sc-1lh-sc',     142 : 'rs2-16m-1sm-sc-1lh-sc',    200 : 'rs2-8m',
  201 : 'rs2-7m',                  202 : 'rs2-6m',                    210 : 'rs2-8m-1mm-sc',            211 : 'rs2-8m-1sm-sc',
  212 : 'rs2-8m-1lh-sc',           220 : 'rs2-7m-1mm-sc',             221 : 'rs2-7m-1sm-sc',            222 : 'rs2-7m-1lh-sc',
  230 : 'rs2-8m-2mm-sc',           231 : 'rs2-8m-2sm-sc',             232 : 'rs2-8m-2lh-sc',            240 : 'rs2-8m-1mm-sc-1sm-sc',
  241 : 'rs2-8m-1mm-sc-1lh-sc',    242 : 'rs2-8m-1sm-sc-1lh-sc',      300 : 'rs2-4r',                   301 : 'rs2-4r-1mm-sc',
  302 : 'rs2-4r-1sm-sc',           303 : 'rs2-4r-1lh-sc',             304 : 'rs2-4r-1fl-st',            311 : 'rs2-4r-2mm-sc',
  312 : 'rs2-4r-2sm-sc',           313 : 'rs2-4r-2lh-sc',             401 : 'ms4128-5',                 410 : 'mach4002-48-4G',
  420 : 'mach4002-24G',            421 : 'mach4002-24G-3X',           425 : 'mach4002-48G',             426 : 'mach4002-48G-3X',
  500 : 'eagle-tx-tx',             501 : 'eagle-tx-mm-sc',            502 : 'eagle-tx-sm-sc',           503 : 'eagle-tx-lh-sc',
  504 : 'eagle-mm-sc-tx',          505 : 'eagle-mm-sc-mm-sc',         506 : 'eagle-mm-sc-sm-sc',        507 : 'eagle-mm-sc-lh-sc',
  520 : 'eagle-fw-tx-tx',          521 : 'eagle-fw-tx-mm-sc',         522 : 'eagle-fw-tx-sm-sc',        523 : 'eagle-fw-tx-lh-sc',
  524 : 'eagle-fw-mm-sc-tx',       525 : 'eagle-fw-mm-sc-mm-sc',      526 : 'eagle-fw-mm-sc-sm-sc',     527 : 'eagle-fw-mm-sc-lh-sc',
  530 : 'eagle-mguard-tx-tx',      531 : 'eagle-mguard-tx-mm-sc',     532 : 'eagle-mguard-tx-sm-sc',    533 : 'eagle-mguard-tx-lh-sc',
  534 : 'eagle-mguard-mm-sc-tx',   535 : 'eagle-mguard-mm-sc-mm-sc',  536 : 'eagle-mguard-mm-sc-sm-sc', 537 : 'eagle-mguard-mm-sc-lh-sc',
  540 : 'eagle20-tx-tx',           541 : 'eagle20-tx-mm-sc',          542 : 'eagle20-tx-sm-sc',	        543 : 'eagle20-tx-lh-sc',
  544 : 'eagle20-mm-sc-tx',        545 : 'eagle20-mm-sc-mm-sc',       546 : 'eagle20-mm-sc-sm-sc',	    547 : 'eagle20-mm-sc-lh-sc',
  550 : 'rr-epl-tx-tx',            551 : 'rr-epl-tx-mm-sc',           600 : 'ms20-0800',                601 : 'ms20-2400',
  620 : 'ms30-0802',               621 : 'ms30-2402',                 700 : 'rs20-0400',                701 : 'rs20-0400m1',
  702 : 'rs20-0400m2',             703 : 'rs20-0800',                 704 : 'rs20-0800m2',              705 : 'rs20-1600',
  706 : 'rs20-1600m2',             707 : 'rs20-2400',                 708 : 'rs20-2400m2',              709 : 'rs20-0900m3',
  710 : 'rs20-1700m3',             711 : 'rs20-2500m3',               720 : 'rs30-0802',                721 : 'rs30-1602',
  722 : 'rs30-2402',               723 : 'rs30-0802m4',               724 : 'rs30-1602m4',              725 : 'rs30-2402m4',
  730 : 'rsb20-8tx',               731 : 'rsb20-8tx-1fx',             732 : 'rsb20-6tx-2fx',            733 : 'rsb20-6tx-3fx',
  734 : 'rsb20-6tx-3sfp',          740 : 'rs40-0009',                 780 : 'cs30-0202',                800 : 'octopus-8m',
  801 : 'octopus-16m',             802 : 'octopus-24m',               803 : 'octopus-8m-2g',            804 : 'octopus-16m-2g',
  810 : 'os-000800',               811 : 'os-000802',                 812 : 'os-001000',                820 : 'osb20-9tx',
  821 : 'osb24-9tx-8poe',          822 : 'osb20-10tx',                823 : 'osb24-10tx-8poe',          900 : 'mar1020',
  901 : 'mar1030',                 902 : 'mar1030-4g',                903 : 'mar1022',                  904 : 'mar1032',
  905 : 'mar1032-4g',              906 : 'mar1120',                   907 : 'mar1130',                  908 : 'mar1130-4g',
  909 : 'mar1122',                 910 : 'mar1132',                   911 : 'mar1132-4g',               912 : 'mar1040',
  913 : 'mar1042',                 914 : 'mar1140',                   915 : 'mar1142',                 1000 : 'rsr30-07sfp-03sfp',
 1001 : 'rsr30-06tp-03combo',     1002 : 'rsr30-06tp-02sfp-02combo', 1003 : 'rsr30-06tp-02sfp-02sfp',  1004 : 'rsr30-08tp-02combo',
 1005 : 'rsr30-08tp-02sfp',       1006 : 'rsr20-06tp-03fx',          1007 : 'rsr20-06tp-02fx',         1008 : 'rsr20-08tp',
 1100 : 'mach100',                1101 : 'mach104-20tx-f',           1102 : 'mach104-20tx-fr',         1103 : 'mach104-20tx-f-4poe',
 1104 : 'mach104-16tx-poep',      1105 : 'mach104-16tx-poep-r',      1106 : 'mach104-16tx-poep-e',     1107 : 'mach104-16tx-poep-2x',
 1108 : 'mach104-16tx-poep-2x-r', 1109 : 'mach104-16tx-poep-2x-e',   1200 : 'eem1' 
};

if(!port)port = 161;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

var soc = open_sock_udp(port);
if (!soc)
  exit (0);

var system = NULL;
var oid_list = NULL;

var descr = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.1.1.0");
var objectid = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.1.2.0");
var uptime = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.1.3.0");
var contact = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.1.4.0");
var name = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.1.5.0");
var location = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.1.6.0");
var services = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.1.7.0");

if (descr || objectid || uptime || contact || name || location || services)
{
  
  system =
    'System information :\n' +
    ' sysDescr     : ' + descr + '\n' +
    ' sysObjectID  : ' + objectid + '\n' +
    ' sysUptime    : ' + uptime + '\n' +
    ' sysContact   : ' + contact + '\n' +
    ' sysName      : ' + name + '\n' +
    ' sysLocation  : ' + location + '\n' +
    ' sysServices  : ' + services + '\n' +
    '\n';

  if (descr)
    set_kb_item(name:"SNMP/sysDesc", value:descr);
  if (objectid)
    set_kb_item(name:"SNMP/OID", value:objectid);
  if (name)
    set_kb_item(name:"SNMP/sysName", value:name);
  if (contact)
    set_kb_item(name:"SNMP/sysContact", value: contact);
  if (location)
    set_kb_item(name:"SNMP/sysLocation", value: location);

  #check for other attributes depending on sysObjectID
  var oids = NULL;
  var val = NULL;
  if (objectid)
  {
    
    #get the manufacture oid
    #Ex: 1.3.6.1.4.1.4329.6.3.2.1.1.2.0 -> 1.3.6.1.4.1.4329
    var matches = pregmatch(pattern:"^(1.3.6.1.4.1.\d+).*$", string:objectid);

    if(!empty_or_null(matches))
      oids = oid_extra_info[matches[1]];

    if(!empty_or_null(oids))
    {
      system += 'Vendor specific information : \n';
      foreach (var key in keys(oids))
      {
        val = snmp_request (socket:soc, community:community, oid: oids[key]);
        if(val)
        {
          #hirschmann returns an int instead of a model so look up the model
          if(oids[key] == '1.3.6.1.4.1.248.14.1.1.1')
            val = hirschmann_product_lookup[val];
          set_kb_item(name:"SNMP/custom/" + key, value: val);
          system += ' ' + key + ' : ' + val + '\n';
        }
      }
    }
  }

  security_report_v4(port:port, extra: system, severity: SECURITY_NOTE, proto:"udp");

}
