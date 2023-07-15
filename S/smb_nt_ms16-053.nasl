#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(91003);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/29");

  script_cve_id("CVE-2016-0187", "CVE-2016-0189");
  script_bugtraq_id(90011, 90012);
  script_xref(name:"MSFT", value:"MS16-053");
  script_xref(name:"MSKB", value:"3158991");
  script_xref(name:"MSKB", value:"3155413");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/18");

  script_name(english:"MS16-053: Cumulative Security Update for JScript and VBScript (3156764)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple remote code execution
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple remote code execution vulnerabilities
in the JScript and VBScript engines due to improper handling of
objects in memory. An unauthenticated, remote attacker can exploit
these vulnerabilities by convincing a user to visit a specially
crafted website or open a Microsoft Office document containing an
embedded ActiveX control, resulting in the execution of arbitrary code
in the context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2016/ms16-053");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, and
Server Core 2008 R2. Alternatively, apply the workaround referenced in
the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0189");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Internet Explorer 11 VBScript Engine Memory Corruption');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = 'MS16-053';
kbs = make_list("3158991", "3155413");

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

vuln = 0;

# VBScript 5.8
# only on Server Core 2008 R2
kb = "3155413";
if (
  hotfix_check_server_core() == 1 &&
  (
    # Windows Server 2008 R2
    # GDR has been dropped, reducing min_version to cover the previous GDR branch
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"Vbscript.dll", version:"5.8.7601.23435", min_version:"5.8.7601.0", dir:"\system32", bulletin:bulletin, kb:kb)
  )
) vuln++;

# VBScript 5.7
kb = "3158991";
if (
  hotfix_check_server_core() == 1 &&
  (
    # Windows 2008 SC only. The advisory also lists full OS installs
    # and Vista, however, these files are included with IE 7, which
    # is unsupported as of Jan 12, 2016. Not constraining this check
    # to SC only will inflate vulnerability counts unnecessarily.
    # https://www.microsoft.com/en-ca/WindowsForBusiness/End-of-IE-support
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"Vbscript.dll", version:"5.7.6002.23956", min_version:"5.7.6002.22000", dir:"\System32", bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"Vbscript.dll", version:"5.7.6002.19642", min_version:"5.7.0.0", dir:"\System32", bulletin:bulletin, kb:kb)
  )
) vuln++;


if (vuln)
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
