#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87259);
  script_version("1.7");
  script_cvs_date("Date: 2018/11/15 20:50:31");

  script_cve_id("CVE-2015-6130");
  script_bugtraq_id(78500);
  script_xref(name:"MSFT", value:"MS15-130");
  script_xref(name:"MSKB", value:"3108670");
  script_xref(name:"IAVA", value:"2015-A-0301");

  script_name(english:"MS15-130: Security Update for Microsoft Uniscribe to Address Remote Code Execution (3108670)");
  script_summary(english:"Checks file versions");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a remote code execution
vulnerability due to improper parsing of fonts by Uniscribe. A remote
attacker can exploit this vulnerability by convincing a user to open a
specially crafted document or visit an untrusted website that contains
specially crafted embedded fonts, resulting in the execution of
arbitrary code in the context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2015/ms15-130");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 7 and 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2018 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');
kb = 3108670;
bulletin = 'MS15-130';
kbs = make_list(kb);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

if (hotfix_check_sp_range(win7:'1') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

if (
    # Windows 7 / 2008 R2 / 2008 R2 Server Core
    hotfix_is_vulnerable(os:'6.1', sp:1, arch:"x64", file:"Usp10.dll", version:"1.626.7601.23259", min_version:"1.626.7601.22700", dir:"\SysWOW64", bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:'6.1', sp:1, arch:"x64", file:"Usp10.dll", version:"1.626.7601.19054", min_version:"1.626.7600.18500", dir:"\SysWOW64", bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:'6.1', sp:1,             file:"Usp10.dll", version:"1.626.7601.23259", min_version:"1.626.7601.22700", dir:"\system32", bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:'6.1', sp:1,             file:"Usp10.dll", version:"1.626.7601.19054", min_version:"1.626.7600.18500", dir:"\system32", bulletin:bulletin, kb:kb)
  )
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  exit(0);
}
else
  audit(AUDIT_HOST_NOT, 'affected');
