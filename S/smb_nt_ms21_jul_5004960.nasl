#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.

#
# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151479);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/07");

  script_cve_id("CVE-2021-34527");
  script_xref(name:"IAVA", value:"2021-A-0299");
  script_xref(name:"MSKB", value:"5004960");
  script_xref(name:"MSFT", value:"MS21-5004960");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/07/20");
  script_xref(name:"CEA-ID", value:"CEA-2021-0034");

  script_name(english:"KB5004960: Windows Server 2012 OOB Security Update RCE (July 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"A remote command execution vulnerability exists in Windows Print Spooler service improperly performs privileged file 
operations. An authenticated, remote attacker can exploit this to bypass and run arbitrary code with SYSTEM privileges.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5004955");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5004960");
  script_set_attribute(attribute:"solution", value:
"Apply Cumulative Update 5004960");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34527");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS21-07';
kbs = make_list(
  '5004960'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:'6.2', 
                   sp:0,
                   rollup_date:'06_2021_07_01',
                   bulletin:bulletin,
                   rollup_kb_list:[5004960])
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
