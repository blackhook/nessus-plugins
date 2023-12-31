#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92017);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/19");

  script_cve_id("CVE-2016-3204");
  script_bugtraq_id(91584);
  script_xref(name:"MSFT", value:"MS16-086");
  script_xref(name:"MSKB", value:"3169658");
  script_xref(name:"MSKB", value:"3169659");
  script_xref(name:"IAVA", value:"2016-A-0177");

  script_name(english:"MS16-086: Cumulative Security Update for JScript and VBScript (3169996)");
  script_summary(english:"Checks the version of Vbscript.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by a remote code execution vulnerability in the
JScript and VBScript engines due to improper handling of objects in
memory. An unauthenticated, remote attacker can exploit this, by
convincing a user to visit a specially crafted website or open a
Microsoft Office document containing an embedded ActiveX control, to
corrupt memory, resulting in the execution of arbitrary code in the
context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2016/ms16-086");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008,
Server Core 2008, and Server Core 2008 R2. Alternatively, apply the
workaround referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3204");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS16-086";
kbs = make_list("3169658", "3169659");

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:"2", win7:"1") <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# Windows 7 & Server 2008 R2 (6.1 !Core) Exclusion
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 7" >< productname) audit(AUDIT_OS_SP_NOT_VULN);
else if ("2008 R2" >< productname && hotfix_check_server_core() == 0) audit(AUDIT_OS_SP_NOT_VULN);

vuln = 0;

kb = "3169658";
if (
  hotfix_check_server_core() == 1 &&
  (
    # Windows Server 2008 R2
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"Vbscript.dll", version:"5.8.7601.23471", min_version:"5.8.7601.0", dir:"\system32", bulletin:bulletin, kb:kb)
  )
) vuln++;

kb = "3169659";
if (
  hotfix_check_server_core() == 1 &&
  (
    # Windows 2008 SC only. The advisory also lists full OS installs
    # and Vista, however, these files are included with IE 7, which
    # is unsupported as of Jan 12, 2016. Not constraining this check
    # to SC only will inflate vulnerability counts unnecessarily.
    # https://www.microsoft.com/en-ca/WindowsForBusiness/End-of-IE-support
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"Vbscript.dll", version:"5.7.6002.23977", min_version:"5.7.6002.20000", dir:"\System32", bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"Vbscript.dll", version:"5.7.6002.19662", min_version:"5.7.0.0", dir:"\System32", bulletin:bulletin, kb:kb)
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
  audit(AUDIT_HOST_NOT, "affected");
}
