#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");
include("global_settings.inc");

if (description)
{
  script_id(162174);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/14");

  script_name(english:"Windows Always Installed Elevated Status");
  script_summary(english:"Checks for Windows Always Installed Elevated Status.");

  script_set_attribute(attribute:"synopsis", value:"Windows AlwaysInstallElevated policy status was found on the remote Windows host");
  script_set_attribute(attribute:"description", value:"Windows AlwaysInstallElevated policy status was found on the remote Windows host.
  You can use the AlwaysInstallElevated policy to install a Windows Installer package with elevated (system) privileges
  This option is equivalent to granting full administrative rights, which can pose a massive security risk. Microsoft strongly discourages the use of this setting.
  ");
  # https://docs.microsoft.com/en-us/windows/win32/msi/alwaysinstallelevated
  script_set_attribute(attribute:"solution", value:"If enabled, disable AlwaysInstallElevated policy per your corporate security guidelines.");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var key = 'Software\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated';
var report, hklm, hku, username, value, port;

# Initialize Registry
registry_init();

##
# HKLM
##

# Non exit because HHKU needs to be checked as well
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:FALSE); 

if (!isnull(hklm))
{
	value = get_registry_value(handle:hklm, item:key);
  RegCloseKey(handle:hklm);

	if (isnull(value) || value == 0) # key does not exist or is 0
		report += 'AlwaysInstallElevated policy is not enabled under HKEY_LOCAL_MACHINE.\n';
	else
		report += 'AlwaysInstallElevated policy is enabled under HKEY_LOCAL_MACHINE.\n';
}
else
{
	spad_log(message:'Failed to connect to HKEY_LOCAL_MACHINE.');
}

###
# HKU
###

hku = registry_hive_connect(hive:HKEY_USERS, exit_on_fail:FALSE);

if (!isnull(hku))
{
  var subkeys = get_registry_subkeys(handle:hku, key:'');
  foreach user_key (subkeys)
  {
    if (user_key =~ "^S-1-5-21-" && user_key !~ "_classes$")
    {
      value = get_registry_value(handle:hku, item:user_key + '\\' + key);

      if (isnull(value) || value == 0)
        report += 'AlwaysInstallElevated policy is not enabled under HKEY_USERS user:' + user_key + '\n';
      else
        report += 'AlwaysInstallElevated policy is enabled under HKEY_USERS user:' + user_key + '\n';
    }
  }
  RegCloseKey(handle:hku);
}
else
{
	spad_log(message:'Failed to connect to HKEY_USERS.');
}

close_registry();

port = kb_smb_transport();

security_report_v4(severity:SECURITY_NOTE, port:port, extra:report);