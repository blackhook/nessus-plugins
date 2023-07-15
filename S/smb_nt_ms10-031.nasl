#
# (C) Tenable Network Security, Inc.
#


include('compat.inc');


if (description)
{
  script_id(46313);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/28");

  script_cve_id("CVE-2010-0815");
  script_bugtraq_id(39931);
  script_xref(name:"MSFT", value:"MS10-031");
  script_xref(name:"MSKB", value:"974945");
  script_xref(name:"MSKB", value:"976321");
  script_xref(name:"MSKB", value:"976380");
  script_xref(name:"MSKB", value:"976382");

  script_name(english:"MS10-031: Vulnerability in Microsoft Visual Basic for Applications Could Allow Remote Code Execution (978213)");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Arbitrary code can be executed on the remote host through Visual
Basic for Applications."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A stack memory corruption vulnerability exists in the way that the
installed version of Visual Basic for Applications (VBA) searches for
ActiveX controls embedded in documents.

If an attacker can trick a user on the affected system into opening a
specially crafted document that supports VBA, this vulnerability could
be leveraged to execute arbitrary code subject to the user's
privileges.  This document could be of any type that supports VBA,
such as a Word document, Excel spreadsheet, PowerPoint presentation,
or one handled by a third-party application.

Note that if an affected copy of VBE6.DLL was installed by a third-
party application, it may be necessary to contact that application's
vendor for an update."
  );
  # https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2010/ms10-031
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2126d8fa");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Office as well as Visual
Basic for Applications Runtime and SDK."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-0815");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_basic");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2022 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS10-031';
kbs = make_list("974945", "976321", "976380", "976382");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

common = hotfix_get_commonfilesdir();
common_x86 = hotfix_get_commonfilesdirx86();

if (!common && !common_x86) 
  exit(1, "hotfix_get_commonfilesdir() and hotfix_get_commonfilesdirx86() failed.");

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:common);
if (!is_accessible_share(share:share))
{
  exit(1, "Can't connect to "+share+" share.");
}

# Determine the applicable KB.
office_ver = hotfix_check_office_version();

if (office_ver)
{
  # Office 2007
  if (office_ver['12.0']) kb = "976321";
  # Office 2003
  else if (office_ver['11.0']) kb = "976382";
  # Office XP
  else if (office_ver['10.0']) kb = "976380";
}
if (!kb) kb = "974945";

x64 = hotfix_check_fversion(path:common+"\Microsoft Shared\VBA\VBA6", file:"Vbe6.dll", version:"6.5.10.53");
if (x64 == HCF_OLDER)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_add_report(bulletin:bulletin, kb:kb);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}

# we should also check x86 common files dir if we dont exit above
x86 = hotfix_check_fversion(path:common_x86+"\Microsoft Shared\VBA\VBA6", file:"Vbe6.dll", version:"6.5.10.53");
if (x86 == HCF_OLDER)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_add_report(bulletin:bulletin, kb:kb);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}

else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
