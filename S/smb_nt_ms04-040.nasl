#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15894);
 script_version("1.51");
 script_cvs_date("Date: 2018/11/15 20:50:29");

 script_cve_id("CVE-2004-1050");
 script_bugtraq_id(11515);
 script_xref(name:"CERT", value:"842160");
 script_xref(name:"MSFT", value:"MS04-040");
 script_xref(name:"MSKB", value:"889293");

 script_name(english:"MS04-040: Cumulative Security Update for Internet Explorer (889293)");
 script_summary(english:"Checks for hotfix 889293");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
client.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Internet Explorer 6 SP1 that
could allow an attacker to execute arbitrary code on the remote host.

To exploit this flaw, an attacker would need to lure a victim on the
remote system into visiting a rogue website.");
 script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2004/ms04-040");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows NT, 2000 and XP.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/25");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/12/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/01");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2018 Tenable Network Security, Inc.");
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

bulletin = 'MS04-040';
kb = '889293';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(nt:'6', win2k:'3,4', xp:'1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

version = get_kb_item("SMB/IE/Version");
if (!version) audit(AUDIT_NOT_INST, "Internet Explorer");
if (!ereg(pattern:"^6\.0*\.2800\.1106", string:version)) exit(0, "Internet Explorer "+version+" is not affected.");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.1", sp:1, file:"Browseui.dll", version:"6.0.2800.1584", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", file:"Browseui.dll", version:"6.0.2800.1584", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"4.0", file:"Browseui.dll", version:"6.0.2800.1584", dir:"\system32", bulletin:bulletin, kb:kb)
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
