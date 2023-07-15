#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(160486);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/04");

  script_name(english:"Server Message Block (SMB) Protocol Version Detection");
  script_summary(english:"Check the version of SMB protocol.");

  script_set_attribute(attribute:"synopsis", value:
  "Verify the version of SMB on the remote host.");
  script_set_attribute(attribute:"description", value:
  "The Server Message Block (SMB) Protocol provides 
  shared access to files and printers across nodes
  on a network.");

  script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?f463096b");
  # https://docs.microsoft.com/en-US/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3
  script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?1a4b3744");
  # https://www.cisa.gov/uscert/ncas/current-activity/2017/01/16/SMB-Security-Best-Practices
  script_set_attribute(attribute:"solution", value:
  "Disable SMB version 1 and block all versions of SMB at
  the network boundary by blocking TCP port 445 with
  related protocols on UDP ports 137-138 and TCP port 139,
  for all boundary devices.");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/04");

  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Windows");
  script_require_ports(139, 445);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Connect to the registry
registry_init();

# Connect to the registry hive
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# Mapping to obtain registry key value
val_map = {
  "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1" : {
    0: "SMBv1 is disabled.",
    1: "SMBv1 is enabled."
  },
  "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB2" : {
    0: "SMBv2 is disabled.",
    1: "SMBv2 is enabled."
  },
  "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB3" : {
    0: "SMBv3 is disabled.",
    1: "SMBv3 is enabled."
  }
};

# Check for disabled and/or null values, and reporting detailed enabled settings
report = '';
report_kvs = make_array();

# Get the registry value. Check to see if it exists, exit & report if the value is not found. Otherwise, set value and report
foreach var key (keys(val_map))
{
  value = get_registry_value(handle:hklm, item:key);
  if(empty_or_null(value))
  {
    report_kvs[key] = "Key not found.";
  }
  else
  {
    report_kvs[key] = val_map[key][value];
  }
}

# Close the key and the registry
RegCloseKey(handle:hklm);
close_registry();

# Check for general enabled/disabled status and add to report
foreach key (keys(report_kvs))
{
  report += ' - ' + key + ' : ' + report_kvs[key] + '\n';
}

# provide the port and the report for that SMB version
security_note(port:kb_smb_transport(), extra:report);
