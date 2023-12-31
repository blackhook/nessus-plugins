#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10944);
 script_version("1.42");
 script_cvs_date("Date: 2018/11/15 20:50:29");

 script_cve_id("CVE-2002-0151");
 script_bugtraq_id(4426);
 script_xref(name:"MSFT", value:"MS02-017");
 script_xref(name:"MSKB", value:"311967");

 script_name(english:"MS02-017: MUP overlong request kernel overflow Patch (311967)");
 script_summary(english:"checks for Multiple UNC Provider Patch (Q311967)");

 script_set_attribute(attribute:"synopsis", value:"A local user can elevate his privileges.");
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a flaw in Multiple UNC Provider
(MUP) service that could allow a local user to execute arbitrary code on
the remote host with SYSTEM privileges.");
 script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2002/ms02-017");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows NT, 2000 and XP.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/04/04");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/04/04");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/04/23");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2018 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS02-017';
kb = '311967';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(nt:'6', win2k:'1,2', xp:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.1", sp:0, file:"Mup.sys", version:"5.1.2600.19", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", file:"Mup.sys", version:"5.0.2195.5080", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"4.0", file:"Mup.sys", version:"4.0.1381.7125", dir:"\system32\drivers", bulletin:bulletin, kb:kb)
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


