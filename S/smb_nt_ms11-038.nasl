#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55118);
  script_version("1.17");
  script_cvs_date("Date: 2018/11/15 20:50:30");

  script_cve_id("CVE-2011-0658");
  script_bugtraq_id(48174);
  script_xref(name:"MSFT", value:"MS11-038");
  script_xref(name:"MSKB", value:"2476490");

  script_name(english:"MS11-038: Vulnerability in OLE Automation Could Allow Remote Code Execution (2476490)");
  script_summary(english:"Checks version of Oleaut32.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host is affected by a remote code execution
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of Windows that is affected by a
remote code execution vulnerability.  An attacker can exploit this by
causing a user to visit a website containing a specially crafted
Windows Metafile (WMF) image.  Exploitation could allow an attacker to
execute arbitrary code with the user's credentials."
  );
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2011/ms11-038");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2018 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS11-038';
kb = "2476490";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Oleaut32.dll", version:"6.1.7601.21669", min_version:"6.1.7601.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Oleaut32.dll", version:"6.1.7601.17567", min_version:"6.1.7601.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Oleaut32.dll", version:"6.1.7600.20861", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Oleaut32.dll", version:"6.1.7600.16722", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Oleaut32.dll", version:"6.0.6002.22551", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Oleaut32.dll", version:"6.0.6002.18357", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Oleaut32.dll", version:"6.0.6001.22816", min_version:"6.0.6001.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Oleaut32.dll", version:"6.0.6001.18565", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003 / XP 64-bit
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Oleaut32.dll", version:"5.2.3790.4807", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP 32-bit
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Oleaut32.dll", version:"5.1.2600.6058", dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
