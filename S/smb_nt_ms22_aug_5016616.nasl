##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
##

include('compat.inc');

if (description)
{
  script_id(163951);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/09");

  script_cve_id(
    "CVE-2022-30133",
    "CVE-2022-30144",
    "CVE-2022-30194",
    "CVE-2022-30197",
    "CVE-2022-33670",
    "CVE-2022-34301",
    "CVE-2022-34302",
    "CVE-2022-34303",
    "CVE-2022-34689",
    "CVE-2022-34690",
    "CVE-2022-34691",
    "CVE-2022-34696",
    "CVE-2022-34699",
    "CVE-2022-34701",
    "CVE-2022-34702",
    "CVE-2022-34703",
    "CVE-2022-34704",
    "CVE-2022-34705",
    "CVE-2022-34706",
    "CVE-2022-34707",
    "CVE-2022-34708",
    "CVE-2022-34709",
    "CVE-2022-34710",
    "CVE-2022-34712",
    "CVE-2022-34713",
    "CVE-2022-34714",
    "CVE-2022-35743",
    "CVE-2022-35744",
    "CVE-2022-35745",
    "CVE-2022-35746",
    "CVE-2022-35747",
    "CVE-2022-35748",
    "CVE-2022-35749",
    "CVE-2022-35750",
    "CVE-2022-35751",
    "CVE-2022-35752",
    "CVE-2022-35753",
    "CVE-2022-35754",
    "CVE-2022-35755",
    "CVE-2022-35756",
    "CVE-2022-35757",
    "CVE-2022-35758",
    "CVE-2022-35759",
    "CVE-2022-35760",
    "CVE-2022-35761",
    "CVE-2022-35762",
    "CVE-2022-35763",
    "CVE-2022-35764",
    "CVE-2022-35765",
    "CVE-2022-35766",
    "CVE-2022-35767",
    "CVE-2022-35768",
    "CVE-2022-35769",
    "CVE-2022-35771",
    "CVE-2022-35792",
    "CVE-2022-35793",
    "CVE-2022-35794",
    "CVE-2022-35795",
    "CVE-2022-35797",
    "CVE-2022-35820"
  );
  script_xref(name:"MSKB", value:"5016616");
  script_xref(name:"MSFT", value:"MS22-5016616");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/08/30");
  script_xref(name:"IAVA", value:"2022-A-0320-S");
  script_xref(name:"IAVA", value:"2022-A-0319-S");

  script_name(english:"KB5016616: Windows 10 Version 20H2 / 21H1 / 21H2 Security Update (August 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5016616. It is, therefore, affected by multiple vulnerabilities

  - Windows Point-to-Point Protocol (PPP) Denial of Service Vulnerability (CVE-2022-35747, CVE-2022-35769)

  - Windows Point-to-Point Protocol (PPP) Remote Code Execution Vulnerability (CVE-2022-30133, CVE-2022-35744)

  - Windows Bluetooth Service Remote Code Execution Vulnerability (CVE-2022-30144)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5016616");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5016616");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5016616");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-30133");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = 'MS22-08';
kbs = make_list(
  '5016616'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

var os_name = get_kb_item("SMB/ProductName");

if (  ( ("enterprise" >< tolower(os_name) || "education" >< tolower(os_name))
      &&
      smb_check_rollup(os:'10',
                    os_build:19042,
                    rollup_date:'08_2022',
                    bulletin:bulletin,
                    rollup_kb_list:[5016616]) 
    )
  ||
    smb_check_rollup(os:'10',
                    os_build:19043,
                    rollup_date:'08_2022',
                    bulletin:bulletin,
                    rollup_kb_list:[5016616])
  || 
    smb_check_rollup(os:'10',
                    os_build:19044,
                    rollup_date:'08_2022',
                    bulletin:bulletin,
                    rollup_kb_list:[5016616])
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
