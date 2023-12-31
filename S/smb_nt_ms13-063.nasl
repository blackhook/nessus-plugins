#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69328);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id(
    "CVE-2013-2556",
    "CVE-2013-3196",
    "CVE-2013-3197",
    "CVE-2013-3198"
  );
  script_bugtraq_id(
    58566,
    61682,
    61683,
    61684
  );
  script_xref(name:"MSFT", value:"MS13-063");
  script_xref(name:"MSKB", value:"2859537");
  script_xref(name:"IAVB", value:"2013-B-0088-S");

  script_name(english:"MS13-063: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (2859537)");
  script_summary(english:"Checks version of ntoskrnl.exe");

  script_set_attribute(attribute:"synopsis", value:
"The Windows kernel on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Windows version installed on the remote host is affected by
multiple vulnerabilities :

  - The Windows kernel is affected by multiple privilege
    escalation vulnerabilities due to a memory corruption
    condition in the NT Virtual DOS Machine (NTVDM).  An
    attacker who successfully exploited these issues could
    run arbitrary code in kernel mode.
    (CVE-2013-3196, CVE-2013-3197, CVE-2013-3198)

  - A vulnerability exists in a security feature of Windows
    due to the improper implementation of Address Space
    Layout Randomization (ASLR).  An attacker could bypass
    the ASLR security feature to load a malicious DLL.
    (CVE-2013-2556)");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-13-192/");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/528339/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2013/ms13-063");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, 2008 R2, and 8.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2556");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS13-063';
kb = '2859537';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'1', win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if (("Windows Embedded" >< productname) || ("Windows Server 2012" >< productname)) exit(0, "The host is running "+productname+" and is, therefore, not affected.");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8 x86
  hotfix_is_vulnerable(os:"6.2", sp:0, arch:"x86", file:"ntoskrnl.exe", version:"6.2.9200.20772", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, arch:"x86", file:"ntoskrnl.exe", version:"6.2.9200.16659", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 7 SP1 x86,x64 / Server 2008 R2 x86,x64
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"ntoskrnl.exe", version:"6.1.7601.22379", min_version:"6.1.7601.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"ntoskrnl.exe", version:"6.1.7601.18205", min_version:"6.1.7600.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows Vista Service Pack 2 x86,x64 / Windows Server 2008 SP2 x86,x64
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ntoskrnl.exe", version:"6.0.6002.23154", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ntoskrnl.exe", version:"6.0.6002.18881", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003 SP2 x86
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x86", file:"ntoskrnl.exe", version:"5.2.3790.5190", min_version:"5.2.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP SP3 x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"ntoskrnl.exe", version:"5.1.2600.6419", min_version:"5.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb)
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
