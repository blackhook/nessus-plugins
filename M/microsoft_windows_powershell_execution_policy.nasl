#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if ( !defined_func("nasl_level") || nasl_level() < 5200 ) exit(0, "Not Nessus 5.2+");

if (description)
{
  script_id(92367);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/12");

  script_name(english:"Microsoft Windows PowerShell Execution Policy");
  script_summary(english:"Report PowerShell's execution policy.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to collect and report the PowerShell execution policy
for the remote host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to collect and report the PowerShell execution policy
for the remote Windows host.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2004-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/ARCH");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

arch = get_kb_item_or_exit('SMB/ARCH');

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

if (isnull(hklm))
{
   close_registry();
   audit(AUDIT_REG_FAIL);
}

report = '';
installed = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\PowerShell\1\Install");
if (installed == 1)
{
  exec_policy_data = make_list();

  exec_policy_path = "SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell\ExecutionPolicy";
  exec_policy = get_registry_value(handle:hklm, item:exec_policy_path);

  if (isnull(exec_policy))
  {
    # Defaults to Restricted.
    exec_policy = "Restricted";
  }

  report += 'HKLM\\'+exec_policy_path + " : " + exec_policy + '\n';
}

if (arch == "x64")
{
  installed = get_registry_value(handle:hklm, item:"SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\Install");
  if (installed == 1)
  {
    exec_policy_path = "SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell\ExecutionPolicy";
    exec_policy = get_registry_value(handle:hklm, item:exec_policy_path);
    if (isnull(exec_policy))
    {
      # Defaults to Restricted.
      exec_policy = "Restricted";
    }

    report += 'HKLM\\'+exec_policy_path + " : " + exec_policy + '\n';
  }
}

RegCloseKey(handle:hklm);

close_registry();

if (strlen(report) > 0)
{
  security_report_v4(extra:report, port:0, severity:SECURITY_NOTE);
}
else
{
  exit(0, "PowerShell not found on system.");
}
