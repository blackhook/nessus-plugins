#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40892);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/05");

  script_cve_id("CVE-2009-1132");
  script_bugtraq_id(36223);
  script_xref(name:"IAVA", value:"2009-A-0078-S");
  script_xref(name:"MSFT", value:"MS09-049");
  script_xref(name:"MSKB", value:"970710");

  script_name(english:"MS09-049: Vulnerability in Wireless LAN AutoConfig Service Could Allow Remote Code Execution (970710)");
  script_summary(english:"Checks version of Wlansvc.dll");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the Wireless
LAN AutoConfig Service.");
  script_set_attribute(attribute:"description", value:
"A remote code execution vulnerability exists in the way that the
Wireless LAN AutoConfig Service (wlansvc) parses specific frames
received on the wireless network.  This vulnerability could allow remote
code execution if a client or server with a wireless network interface
enabled receives specially crafted wireless frames.  If a user is logged
on with administrative user rights, an attacker who successfully
exploited this vulnerability could take complete control of an affected
system.");
  # https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2009/ms09-049
  script_set_attribute(attribute:"see_also", value:"https://www.nessus.org/u?526b78db");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows Vista and 2008.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-1132");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = 'MS09-049';
kb = '970710';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'0,2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Wlansvc.dll", version:"6.0.6002.22170", min_version:"6.0.6002.20000", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Wlansvc.dll", version:"6.0.6002.18064",                               dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Wlansvc.dll", version:"6.0.6001.22468", min_version:"6.0.6001.20000", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Wlansvc.dll", version:"6.0.6001.18288",                               dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"Wlansvc.dll", version:"6.0.6000.21082", min_version:"6.0.6000.20000", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"Wlansvc.dll", version:"6.0.6000.16884",                               dir:"\System32", bulletin:bulletin, kb:kb)
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
