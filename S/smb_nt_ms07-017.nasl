#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(24911);
 script_version("1.38");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/05");

  script_cve_id(
    "CVE-2006-5586",
    "CVE-2006-5758",
    "CVE-2007-0038",
    "CVE-2007-1211",
    "CVE-2007-1212",
    "CVE-2007-1213",
    "CVE-2007-1215",
    "CVE-2007-1765"
  );
 script_bugtraq_id(23194, 23273, 23275, 23276, 23277, 23278);
 script_xref(name:"MSFT", value:"MS07-017");
 script_xref(name:"MSKB", value:"925902");
 
 script_xref(name:"IAVA", value:"2007-A-0020-S");
 script_xref(name:"CERT", value:"191609");
 script_xref(name:"EDB-ID", value:"3617");
 script_xref(name:"EDB-ID", value:"3634");
 script_xref(name:"EDB-ID", value:"3635");
 script_xref(name:"EDB-ID", value:"3636");
 script_xref(name:"EDB-ID", value:"3652");
 script_xref(name:"EDB-ID", value:"16526");
 script_xref(name:"EDB-ID", value:"16698");

 script_name(english:"MS07-017: Vulnerabilities in GDI Could Allow Remote Code Execution (925902)");
 script_summary(english:"Determines the presence of update 925902");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the email
client or the web browser.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows with a bug in the
Animated Cursor (ANI) handling routine that could allow an attacker to
execute arbitrary code on the remote host by sending a specially crafted
email or by luring a user on the remote host into visiting a rogue web
site.

Additionally, the system is vulnerable to :

  - Local Privilege Elevation (GDI, EMF, Font Rasterizer)

  - Denial of Service (WMF)");
  # https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2007/ms07-017
  script_set_attribute(attribute:"see_also", value:"https://www.nessus.org/u?844ca267");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003 and
Vista.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Windows ANI LoadAniIcon() Chunk Size Stack Buffer Overflow (SMTP)');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/06");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/04/03");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/04/03");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"stig_severity", value:"I");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2007-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

bulletin = 'MS07-017';
kb = "925902";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2', win2003:'0,2', vista:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"User32.dll", version:"6.0.6000.16438", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"User32.dll", version:"6.0.6000.20537", min_version:"6.0.6000.20000", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"User32.dll", version:"5.2.3790.4033", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:1, file:"User32.dll", version:"5.2.3790.2892", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:0, file:"User32.dll", version:"5.2.3790.651", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", file:"User32.dll", version:"5.1.2600.3099", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", file:"User32.dll", version:"5.0.2195.7133", dir:"\System32", bulletin:bulletin, kb:kb)
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

