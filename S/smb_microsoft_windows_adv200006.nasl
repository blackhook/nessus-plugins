#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134942);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/17");

  script_name(english:"Microsoft Windows Type 1 Font Parsing Remote Code Execution Vulnerability (ADV200006)");
  script_summary(english:"Checks the Windows version and mitigative measures.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a font parsing vulnerability.");
  script_set_attribute(attribute:"description", value:
"Two remote code execution vulnerabilities exist in Microsoft Windows when the Windows Adobe Type Manager Library
improperly handles a specially-crafted multi-master font - Adobe Type 1 PostScript format. There are multiple ways an
attacker could exploit the vulnerability, such as convincing a user to open a specially crafted document or viewing it
in the Windows Preview pane.

Note that Microsoft does not recommend that IT administrators running Windows 10 implement the workarounds described in
ADV200006. Please see the vendor advisory for more information.");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV200006
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f05dd830");
  script_set_attribute(attribute:"see_also", value:"https://www.kb.cert.org/vuls/id/354840/");
  script_set_attribute(attribute:"solution", value:
"Microsoft has provided additional details and guidance in the ADV200006 advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"RCE");

  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/26");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl","smb_check_rollup.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion", "SMB/WindowsVersionBuild");

  script_require_ports(139, 445);

  exit(0);
}

include('smb_hotfixes_fcheck.inc');
include('smb_hotfixes.inc');
include('smb_func.inc');
include('misc_func.inc');
include('smb_reg_query.inc');

# As per the advisory, while Windows 10 is technically affected, MS recommends upgrading to Windows 10 as a fix and
# specifically recommends not implementing the workarounds for Windows 10
# so if we are Windows 10 we just audit out
if (hotfix_check_sp_range(win10:'0') > 0)
  exit(0, "Microsoft does not recommend that IT administrators running Windows 10 implement the workarounds described in ADV200006. Please see the vendor advisory for more information.");

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0',  win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

my_os = get_kb_item("SMB/WindowsVersion");
rollup_vuln = TRUE;
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname)
 audit(AUDIT_OS_SP_NOT_VULN);
if ("Vista" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

if(my_os == "6.0")
  rollup_vuln = smb_check_rollup(os:"6.0",
                  sp:2,
                  rollup_date:"04_2020",
                  bulletin:bulletin,
                  rollup_kb_list:[4550951, 4550957]);
else if (my_os == "6.1")
  rollup_vuln = smb_check_rollup(os:"6.1",
                  sp:1,
                  rollup_date:"04_2020",
                  bulletin:bulletin,
                  rollup_kb_list:[4550964, 4550965]);
else if (my_os == "6.2")
  rollup_vuln = smb_check_rollup(os:"6.2",
                  sp:0,
                  rollup_date:"04_2020",
                  bulletin:bulletin,
                  rollup_kb_list:[4550971, 4550917]);
else if (my_os == "6.3")
  rollup_vuln = smb_check_rollup(os:"6.3",
                  sp:0,
                  rollup_date:"04_2020",
                  bulletin:bulletin,
                  rollup_kb_list:[4550961, 4550970]);

if(!rollup_vuln) audit(AUDIT_HOST_NOT, 'affected');

port = kb_smb_transport();

# first we check if atmfd is disable as this is a valid workaround
# if HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\DisableATMFD does not exist or exists and is not set to 1
# then we could be vuln (if atmfd.dll exists)
disable_atmfd_key = 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\DisableATMFD';

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
disable_atmfd_val = get_registry_value(handle:hklm, item:disable_atmfd_key);
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

# if it exists and is set to 1 then the workaround is applied and we are not vuln
if (!isnull(disable_atmfd_val) && (disable_atmfd_val == '1'))
  audit(AUDIT_HOST_NOT, 'affected');

# if it is not disabled, we need to check if the atmfd.dll file has been renamed
system_root = hotfix_get_systemroot();
atmfd_dll_file = hotfix_append_path(path:system_root, value:'\\System32\\atmfd.dll');
if (!hotfix_file_exists(path:atmfd_dll_file))
  audit(AUDIT_HOST_NOT, 'affected');

report =
  'File checked:\n' +
  atmfd_dll_file + ': not renamed\n' +
  '\n' +
  'Registry value checked:\n' +
  disable_atmfd_key + ': ' + obj_rep(disable_atmfd_val) + '\n';

security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
