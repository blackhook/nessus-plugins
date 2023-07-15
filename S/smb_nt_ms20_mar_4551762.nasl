#
# (C) Tenable Network Security, Inc.
#






# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(134428);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/23");

  script_cve_id("CVE-2020-0796");
  script_xref(name:"MSKB", value:"4551762");
  script_xref(name:"MSFT", value:"MS20-4551762");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/08/10");
  script_xref(name:"CEA-ID", value:"CEA-2020-0028");

  script_name(english:"KB4551762: Windows 10 Version 1903 and Windows 10 Version 1909 OOB Security Update (ADV200005)(CVE-2020-0796)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4551762. It is, therefore, affected by a remote code execution
vulnerability. The vulnerability exists in the way that the Microsoft Server Message Block 3.1.1
(SMBv3) protocol handles certain requests. An attacker who successfully exploited the vulnerability could gain the
ability to execute code on the target server or client.");
  # https://support.microsoft.com/en-us/help/4551762/windows-10-update-kb4551762
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ab6efe1b");
  script_set_attribute(attribute:"solution", value:
"Apply Cumulative Update KB4551762.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0796");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SMBv3 Compression Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = "MS20-03";
kbs = make_list('4551762');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"18362",
                   rollup_date:"03_2020_2",
                   bulletin:bulletin,
                   rollup_kb_list:[4551762])
  ||
  smb_check_rollup(os:"10",
                 sp:0,
                 os_build:"18363",
                 rollup_date:"03_2020_2",
                 bulletin:bulletin,
                 rollup_kb_list:[4551762])
)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}

