#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(159929);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_name(english:"Windows LSA Protection Status");
  script_summary(english:"Checks for Windows LSA Protection Status.");

  script_set_attribute(attribute:"synopsis", value:"Windows LSA Protection is disabled on the remote Windows host.");
  script_set_attribute(attribute:"description", value:"The LSA Protection validates users for local and remote sign-ins 
  and enforces local security policies to prevent reading memory and code injection by non-protected processes. 
  This provides added security for the credentials that the LSA stores and manages. This protects against Pass-the-Hash 
  or Mimikatz-style attacks.");
  # https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
  #script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb8c8c37");
  script_set_attribute(attribute:"solution", value:"Enable LSA Protection per your corporate security guidelines.");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/20");
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
var hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# Mapping to obtain registry key value and make reporting logic simple
var val_map = {
  "SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL" : {
    0 : "LSA Protection is disabled.",
    1 : "LSA Protection is enabled."
  }
};

var report = "";
# Obtain registry value. Check for existence, exit & report if not found, otherwise set value and report
foreach var key (keys(val_map))
{
  var value = get_registry_value(handle:hklm, item:key);
  if (empty_or_null(value))
  {
   report = '\n' + "LSA Protection Key \SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL not found." + '\n';
  }
  else
  {
    report = '\n' + val_map[key][value] + '\n';
  }
}

# Close Registry and report
RegCloseKey(handle:hklm);
close_registry();
security_note(port:kb_smb_transport(), extra: report);
