#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(47761);
  script_version ("1.6");
  script_cvs_date("Date: 2019/11/22");
 
  script_name(english:"VMware Virtual Machine detection (dmidecode)");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote host seems to be a VMware virtual machine." );
 script_set_attribute(attribute:"description", value:
"According to the DMI information, the remote host is a VMware virtual
machine. 

Since it is physically accessible through the network, ensure that its
configuration matches your organization's security policy." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"agent", value:"all");

 script_set_attribute(attribute:"plugin_publication_date", value: "2010/07/19");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_end_attributes();

 
  script_summary(english:"Look for VMware in dmidecode output");
   script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2010-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"General");
  script_dependencies("dmi_system_info.nasl", "vmware_detect.nasl");
  script_require_ports("DMI/System/ProductName");
  script_exclude_keys("Host/VM/vmware");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

if (get_kb_item("Host/VM/vmware"))
  exit(0, "VMware was already detected.");

sys = get_kb_item_or_exit("DMI/System/ProductName");

if (chomp(sys) == "VMware Virtual Platform")
{
  security_note(port: 0);
  set_kb_item(name: "Host/VM/vmware", value: TRUE);
}

