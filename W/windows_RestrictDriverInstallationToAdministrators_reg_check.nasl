#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##
include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158243);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/22");

  script_name(english:"Windows Operating System Hardening Measure (RestrictDriverInstallationToAdministrators)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is missing an operating system hardening measure.");
  script_set_attribute(attribute:"description", value:
"The remote system may be in a vulnerable state to exploitation by having the 
HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint\RestrictDriverInstallationToAdministrators registry
key set to 0.");
  # https://support.microsoft.com/en-us/topic/kb5005010-restricting-installation-of-new-printer-drivers-after-applying-the-july-6-2021-updates-31b91c02-05bc-4ada-a7ea-183b129578a7
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a4e8dad8");
  # https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9896731b");
  script_set_attribute(attribute:"solution", value:
"Update the DWORD registry value RestrictDriverInstallationToAdministrators under: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint to 1");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) 
  audit(AUDIT_SHARE_FAIL, share);

hotfix_check_fversion_init();
registry_init();
var hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
var key = '\\Software\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint\\RestrictDriverInstallationToAdministrators';
var value = get_registry_value(handle:hklm, item:key);
RegCloseKey(handle:hklm);

if (!isnull(value) && value == 0)
{

  var report = '\n Nessus detected the following insecure registry key configuration:\n';
  report += '    - ' + key + ' is present in the registry with value ' + value + '\n';

  hotfix_add_report(report);

  hotfix_security_note();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
