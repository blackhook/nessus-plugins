#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55126);
  script_version("1.18");
  script_cvs_date("Date: 2018/11/15 20:50:31");

  script_cve_id("CVE-2011-1249");
  script_bugtraq_id(48198);
  script_xref(name:"EDB-ID", value:"18755");
  script_xref(name:"MSFT", value:"MS11-046");
  script_xref(name:"MSKB", value:"2503665");

  script_name(english:"MS11-046: Vulnerability in Ancillary Function Driver Could Allow Elevation of Privilege (2503665)");
  script_summary(english:"Checks version of Afd.sys");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a driver that allows privilege
escalation."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host contains a version of the Ancillary Function
Driver (afd.sys) that does not properly validate input before passing it
from user mode to the kernel.

An attacker with local access to the affected system could exploit this
issue to execute arbitrary code in kernel mode and take complete control
of the affected system."
  );
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2011/ms11-046");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
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

bulletin = 'MS11-046';
kb = "2503665";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Afd.sys", version:"6.1.7601.21712", min_version:"6.1.7601.21000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Afd.sys", version:"6.1.7601.17603", min_version:"6.1.7601.17000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Afd.sys", version:"6.1.7600.20951", min_version:"6.1.7600.20000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Afd.sys", version:"6.1.7600.16802", min_version:"6.1.7600.16000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Windows Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Afd.sys", version:"6.0.6002.22629", min_version:"6.0.6002.22000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Afd.sys", version:"6.0.6002.18457", min_version:"6.0.6002.18000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Afd.sys", version:"6.0.6001.22905", min_version:"6.0.6001.22000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Afd.sys", version:"6.0.6001.18639", min_version:"6.0.6001.18000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Windows 2003 / XP 64-bit
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Afd.sys", version:"5.2.3790.4828",                                dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Windows XP 32-bit
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Afd.sys", version:"5.1.2600.6081",                                dir:"\system32\drivers", bulletin:bulletin, kb:kb)
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
