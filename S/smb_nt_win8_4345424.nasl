#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119150);
  script_version("1.1");
  script_cvs_date("Date: 2018/11/27 12:24:14");
  
  script_xref(name:"MSKB", value:"4345424");

  script_name(english:"Windows 8.1 and Server 2012 R2 KB4345424 Update");
  script_summary(english:"Checks the version of the DLL files.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is missing 4345424 update");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing update 4345424. This update 
includes quality improvements. No new operating system features are 
being introduced in this update. Key changes include:

  - Addressed issue in which some devices may experience stop error
  0xD1 when you run network monitoring workloads.

  - Addresses an issue that may cause the restart of the SQL Server 
  service to fail with the error, 'Tcp port is already in use'.

  - Addresses an issue that occurs when an administrator tries to 
  stop the World Wide Web Publishing Service (W3SVC). The W3SVC 
  remains in a 'stopping' state, but cannot fully stop or it cannot
   be restarted.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4345424/title");
  script_set_attribute(attribute:"solution", value:
"Apply Update KB4345424");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "smb_check_rollup.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

kbs = make_list("4345424");

vuln = 0;

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
win_ver = get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (win_ver != "6.3")
  audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

if ("2012 R2" >!< productname && "Windows 8" >!< productname)
  audit(AUDIT_OS_NOT, "Windows 8 or Windows Server 2012 R2");

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share))
  audit(AUDIT_SHARE_FAIL, share);

if (
  # 4345424
  # x86
    hotfix_is_vulnerable(os:"6.3", sp:0, file:"hal.dll", version:"6.3.9600.19067", min_version:"6.3.9600.16000", dir:"\system32", kb:"4345424", arch:"x86")
  ||
  # x64
    hotfix_is_vulnerable(os:"6.3", sp:0, file:"hal.dll", version:"6.3.9600.18969", min_version:"6.3.9600.16000", dir:"\system32", kb:"4345424", arch:"x64")

)
{
  hotfix_security_note();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}

