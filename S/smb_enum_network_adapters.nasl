#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103871);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/01");

  script_xref(name:"IAVT", value:"0001-T-0758");

  script_name(english:"Microsoft Windows Network Adapters");
  script_summary(english:"Enumerates the installed network adapters.");

  script_set_attribute(attribute:"synopsis", value:
"Identifies the network adapters installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"Using the supplied credentials, this plugin enumerates and reports
the installed network adapters on the remote Windows host.");
  script_set_attribute(attribute:"solution", value:
"Make sure that all of the installed network adapters agrees with your
organization's acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");

if (get_kb_item("SMB/not_windows")) audit(AUDIT_OS_NOT, "Windows");

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

adapter_subkeys = get_registry_subkeys(handle:hklm, key:"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}");
if (isnull(adapter_subkeys))
  audit(AUDIT_REG_FAIL);

report = "";
adapters = make_array();
foreach adapter_subkey (adapter_subkeys)
{
  if(!preg(pattern:"^\d{4}$", string:adapter_subkey))
    continue;

  item_base = "SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\" + adapter_subkey;

  # 132 is physical network adapters, both wired and wireless
  characteristics = get_registry_value(handle:hklm, item:item_base + "\Characteristics");
  if (characteristics != 132)
    continue;

  adapters[adapter_subkey] = make_array();
  adapters[adapter_subkey]["DriverDesc"] = get_registry_value(handle:hklm, item:item_base + "\DriverDesc");
  adapters[adapter_subkey]["DriverVersion"] = get_registry_value(handle:hklm, item:item_base + "\DriverVersion");
  adapters[adapter_subkey]["DeviceInstanceID"] = get_registry_value(handle:hklm, item:item_base + "\DeviceInstanceID");

  kb_base = "SMB/Registry/HKLM/" + str_replace(find:"\", replace:"/", string:item_base);
  set_kb_item(name:kb_base + "/DriverDesc", value:adapters[adapter_subkey]["DriverDesc"]);
  set_kb_item(name:kb_base + "/DriverVersion", value:adapters[adapter_subkey]["DriverVersion"]);
  if (!isnull(adapters[adapter_subkey]["DeviceInstanceID"]))
    set_kb_item(name:kb_base + "/DeviceInstanceID", value:adapters[adapter_subkey]["DeviceInstanceID"]);

  report += "Network Adapter Driver Description : " + adapters[adapter_subkey]["DriverDesc"] + '\n';
  report += "Network Adapter Driver Version     : " + adapters[adapter_subkey]["DriverVersion"] + '\n';
  report += '\n';
}

RegCloseKey(handle:hklm);
close_registry();

if (empty_or_null(report))
  exit(0, "Nessus could not get network adapter information from the system.");

port = kb_smb_transport();
security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);

