#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(48763);
  script_version("1.7");
  script_cvs_date("Date: 2019/12/20");

  script_name(english:"Microsoft Windows 'CWDIllegalInDllSearch' Registry Setting");
  script_summary(english:"Reports value of CWDIllegalInDllSearch ");

  script_set_attribute(
    attribute:"synopsis",
    value:
"CWDIllegalInDllSearch Settings: Improper settings could allow code execution attacks."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Windows Hosts can be hardened against DLL hijacking attacks by
 setting the The 'CWDIllegalInDllSearch' registry entry in to 
 one of the following settings:

  - 0xFFFFFFFF (Removes the current working directory
    from the default DLL search order)

  - 1 (Blocks a DLL Load from the current working
    directory if the current working directory is set
    to a WebDAV folder)

  - 2 (Blocks a DLL Load from the current working
    directory if the current working directory is set
    to a remote folder)"
  );
  # https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2010/2269637
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c574c56");
  # https://support.microsoft.com/en-us/help/2264107/a-new-cwdillegalindllsearch-registry-entry-is-available-to-control-the
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5234ef0c");
  script_set_attribute(
    attribute:"solution",
    value:"n/a"
  );
  script_set_attribute(attribute:"risk_factor",value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/26");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");
include("smb_reg_query.inc");
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');


port = get_kb_item_or_exit('SMB/transport');

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key  = "SYSTEM\CurrentControlSet\Control\Session Manager\CWDIllegalInDllSearch";
value = get_registry_value(handle:hklm, item:key);

RegCloseKey(handle:hklm);
close_registry();

if (empty_or_null(value))
  kb_val = 'Registry Key Empty or Missing';  
else if (value == 0xffffffff) 
  kb_val = '0xffffffff';
else kb_val = string(value);
set_kb_item(name:key, value:kb_val);
report =
  '\n  Name  : '+ key +
  '\n  Value : ' + kb_val + '\n';
security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
