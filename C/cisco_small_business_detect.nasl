###
#  (C) Tenable, Inc.
###

include("compat.inc");

if (description)
{
 script_id(122115);
 script_version("1.7");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/15");

  script_xref(name:"IAVT", value:"0001-T-0558");

 script_name(english:"Cisco Small Business Router SNMP Detection");
 script_summary(english:"Detect Cisco Small Business Router via SNMP");

 script_set_attribute(attribute:"synopsis", value:
"Nessus detected a remote router");
 script_set_attribute(attribute:"description", value:
"Using SNMP, Nessus has determined that the remote host is a Cisco Small Business Router");
 # https://www.cisco.com/c/en/us/solutions/small-business/routers.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f58bf406");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/12");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv320_dual_gigabit_wan_vpn_router");
 script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv325_dual_gigabit_wan_vpn_router");
 script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:small_business_router");

 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_set_attribute(attribute:"hardware_inventory", value:"True");
 script_set_attribute(attribute:"os_identification", value:"True");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CISCO");

 script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_dependencies("os_fingerprint_snmp.nasl");
 script_require_keys("Host/OS/SNMP");
 script_require_ports("Services/udp", 161);
 exit(0);
}

model = NULL;
version = NULL;

os = get_kb_item_or_exit("Host/OS/SNMP");
if ("Cisco Small Business" >!< os)
  audit(AUDIT_HOST_NOT, "Cisco Small Business Router");

version = pregmatch(pattern:"\s([0-9]+\.[0-9.]+)$", string:os);
if (!isnull(version) && !isnull(version[1]))
  version = version[1];
else
  version = "unknown";
set_kb_item(name:"Cisco/Small_Business_Router/Version", value:version);


model = get_kb_item("Host/OS/SNMP/Device");
if (isnull(model))
  model = "unknown";
set_kb_item(name:"Cisco/Small_Business_Router/Model", value:model);

report = '\n  Model           : ' + model +
         '\n  Software version : ' + version +
         '\n';

security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);

exit(0);



