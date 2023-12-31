#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25883);
 script_version("1.36");
 script_cvs_date("Date: 2018/11/15 20:50:30");

 script_cve_id(
  "CVE-2007-0319",
  "CVE-2007-0943",
  "CVE-2007-2216",
  "CVE-2007-2240",
  "CVE-2007-2928",
  "CVE-2007-2929",
  "CVE-2007-3041"
 );
 script_bugtraq_id(25288, 25289, 25295, 25311, 25312);
 script_xref(name:"MSFT", value:"MS07-045");
 script_xref(name:"MSKB", value:"937143");
 
 script_xref(name:"CERT", value:"426737");
 script_xref(name:"CERT", value:"570705");
 script_xref(name:"CERT", value:"599657");
 script_xref(name:"CERT", value:"747233");
 script_xref(name:"EDB-ID", value:"30490");

 script_name(english:"MS07-045: Cumulative Security Update for Internet Explorer (937143)");
 script_summary(english:"Determines the presence of update 937143");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
client.");
 script_set_attribute(attribute:"description", value:
"The remote host is missing IE Cumulative Security Update 937143.

The remote version of IE is potentially vulnerable to several flaws that
may allow an attacker to execute arbitrary code on the remote host.");
 script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2007/ms07-045");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003 and
Vista.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(16, 399);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/08/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/14");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2018 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

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

bulletin = 'MS07-045';
kb = '937143';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2', win2003:'1,2', vista:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Mshtml.dll", version:"7.0.6000.20643", min_version:"7.0.6000.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Mshtml.dll", version:"7.0.6000.16527", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.2", sp:1, file:"Mshtml.dll", version:"6.0.3790.2954", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"6.0.3790.4106", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", file:"Mshtml.dll", version:"7.0.6000.16525", min_version:"7.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", file:"Mshtml.dll", version:"7.0.6000.20641", min_version:"7.0.6000.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Mshtml.dll", version:"6.0.2900.3157", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Mshtml.dll", version:"7.0.6000.16525", min_version:"7.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.0", file:"Mshtml.dll", version:"6.0.2800.1597", min_version:"6.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", file:"Mshtml.dll", version:"5.0.3854.1200", dir:"\system32", bulletin:bulletin, kb:kb)
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
