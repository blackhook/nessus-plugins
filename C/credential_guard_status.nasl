#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(159817);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/25");

  script_name(english:"Windows Credential Guard Status");
  script_summary(english:"Checks for Windows Credential Guard Status.");

  script_set_attribute(attribute:"synopsis", value:"Windows Credential Guard is disabled on the remote Windows host.");
  script_set_attribute(attribute:"description", value:"Windows Credential Guard is disabled on the remote Windows host.
  Credential Guard prevents attacks such as such as Pass-the-Hash or
  Pass-The-Ticket by protecting NTLM password hashes, Kerberos Ticket
  Granting Tickets, and credentials stored by applications as domain
  credentials.");
  # https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb8c8c37");
  script_set_attribute(attribute:"solution", value:"Enable Credential Guard per your corporate security guidelines.");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/18");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "os_fingerprint_msrprc.nasl", "os_fingerprint_smb.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");
include("global_settings.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Initialize Registry
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# Creating registry key:value mapping for reporting output on specific enabled settings of all three essential keys
kv_mappings = {
  "System\CurrentControlSet\Control\DeviceGuard\EnableVirtualizationBasedSecurity" : {
    0 : "is disabled.",
    1 : "is enabled."
  },
  "System\CurrentControlSet\Control\DeviceGuard\RequirePlatformSecurityFeatures" : {
    0 : "is disabled.",
    1 : "is enabled with Secure Boot.",
    3 : "is enabled with Secure Boot and DMA protection."
  },
  "System\CurrentControlSet\Control\LSA\LsaCfgFlags" : {
    0 : "is disabled.",
    1 : "is enabled with UEFI Lock.",
    2 : "is enabled without lock."
  }
};

# For reporting, checking for disabled and/or null values, and reporting detailed enabled settings
general_report = '';
detail_report = '';
report_kvs = make_array();

# assign values to key in array for inspection and reporting
foreach key (keys(kv_mappings))
{
  value = get_registry_value(handle:hklm, item:key);
  if (empty_or_null(value))
  {
    report_kvs[key] = "Key not found.";
  }
  else
  {
    report_kvs[key] = kv_mappings[key][value];
  }
}

RegCloseKey(handle:hklm);
close_registry();

# Check for general enabled/dsiabled status and add to general_report
i = 0;
foreach key (keys(report_kvs))
{
  if (report_kvs[key] == "is disabled." || report_kvs[key] == "Key not found.")
  i += 1;
}
if (i>0)
{
  general_report = '\n' + 'Windows Credential Guard is not fully enabled.\n' +
            'The following registry keys have not been set :\n';
}
else
{
  general_report = '\n' + 'Windows Credential Guard is fully enabled.\n' +
            'Please see below for full details on key settings :\n';
}

# Report detailed enabled settings. This includes disabled and keys that were not found.
foreach key (keys(report_kvs))
{
    detail_report += '  - ' + key + ' : ' + report_kvs[key] + '\n';
}
security_note(port:kb_smb_transport(), extra: general_report + detail_report);
