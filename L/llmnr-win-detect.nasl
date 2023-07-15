#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if(description)
{
  script_id(160301);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/29");

  script_name(english:"Link-Local Multicast Name Resolution (LLMNR) Service Detection");
  script_summary(english:"Checks the status of the LLMNR service.");

  script_set_attribute(attribute:"synopsis", value:
  "Verify status of the LLMNR service on the remote host.");
  script_set_attribute(attribute:"description", value:
  "The Link-Local Multicast Name Resolution (LLMNR) service
  allows both IPv4 and IPv6 hosts to perform name resolution 
  for hosts on the same local link");

  script_set_attribute(attribute:"see_also", value: "http://technet.microsoft.com/en-us/library/bb878128.aspx");
  script_set_attribute(attribute:"solution", value:
  "Make sure that use of this software conforms to your organization's
  acceptable use and security policies.");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/28");

  script_set_attribute(attribute:"risk_factor", value:"None" );
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english: "Service detection");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("install_func.inc");
include("spad_log_func.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');

# Connect to the registry
registry_init();

# Connect to the registry hive
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# The key to search for
var val_map = {
  "SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast" : {
    0 : "LLMNR Status is disabled.",
    1 : "LLMNR Status is enabled."
  }
};

var report = "";
# Obtain registry value. Check for existence, exit & report if not found, otherwise set value and report
foreach var key (keys(val_map))
{
  var value = get_registry_value(handle:hklm, item:key);
  if (empty_or_null(value))
  {
   report = '\n' + "LLMNR Key SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast not found." + '\n';
  }
  else
  {
    report = '\n' + val_map[key][value] + '\n';
  }
}

# Close Registry and report
RegCloseKey(handle:hklm);
close_registry();
security_report_v4(port: kb_smb_transport(), severity: SECURITY_NOTE, extra: report);
