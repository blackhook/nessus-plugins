#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#
include("compat.inc");

if (description)
{
  script_id(108757);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/17");

  script_cve_id("CVE-2018-1038");
  script_xref(name:"MSKB", value:"4100480");
  script_xref(name:"MSFT", value:"MS18-4100480");

  script_name(english:"KB4100480: Windows Kernel Elevation of Privilege Vulnerability");
  script_summary(english:"Checks for rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by elevation of privilege vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4100480. It is,
therefore, affected by an elevation of privilege vulnerability that
exists when the Windows kernel fails to properly handle objects in
memory. An attacker who successfully exploited this vulnerability
could run arbitrary code in kernel mode. An attacker could then
install programs; view, change, or delete data; or create new
accounts with full user rights.

To exploit this vulnerability, an attacker would first have to log
on to the system. An attacker could then run a specially crafted
application to take control of an affected system. ");
  # https://support.microsoft.com/en-us/help/4100480/windows-kernel-update-for-cve-2018-1038
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a34a061");
  script_set_attribute(attribute:"see_also", value:"https://blog.frizk.net/2018/03/total-meltdown.html");
  script_set_attribute(attribute:"see_also", value:"https://github.com/ufrisk/pcileech");
  script_set_attribute(attribute:"solution", value:
"Apply KB4100480.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1038");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
arch = get_kb_item_or_exit('SMB/ARCH');
if (arch != "x64") audit(AUDIT_ARCH_NOT, "x64", arch);

bulletin = "MS18-03";
kbs = make_list('4100480');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win7:'1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# 4100480 got superseded by a sec only update, 4093108
if (get_kb_item("smb_rollup/04_2018/sec") == "4093108") audit(AUDIT_HOST_NOT, "affected");

if (
  smb_check_rollup(os:"6.1",
                   sp:1,
                   rollup_date:"03_2018_3",
                   bulletin:bulletin,
                   rollup_kb_list:[4100480])
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
