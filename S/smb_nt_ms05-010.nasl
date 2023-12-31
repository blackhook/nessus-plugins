#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(16325);
 script_version("1.34");
 script_cvs_date("Date: 2018/11/15 20:50:29");

 script_cve_id("CVE-2005-0050");
 script_bugtraq_id(12481);
 script_xref(name:"MSFT", value:"MS05-010");
 script_xref(name:"CERT", value:"130433");
 script_xref(name:"MSKB", value:"885834");

 script_name(english:"MS05-010: Vulnerability in the License Logging Service (885834)");
 script_summary(english:"Determines if hotfix 885834 has been installed");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code can be executed on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a flaw in the Logging Service
that could allow an attacker to execute arbitrary code on the remote
host.

To exploit this flaw, an attacker would need to send a malformed packet
to the remote logging service, and would be able to either execute
arbitrary code on the remote host or to perform a denial of service.");
 script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2005/ms05-010");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000 and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_cwe_id(20);

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/08");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/02/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/08");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2018 Tenable Network Security, Inc.");
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

bulletin = 'MS05-010';
kb = '885834';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(nt:'6', win2k:'3,4', win2003:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_nt_server() <= 0) exit(0, "The Windows host is not an NT Server.");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.2", sp:0, file:"Llssrv.exe", version:"5.2.3790.248", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", file:"Llssrv.exe", version:"5.0.2195.7021", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"4.0", file:"Llssrv.exe", version:"4.0.1381.7345", dir:"\system32", bulletin:bulletin, kb:kb)
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
