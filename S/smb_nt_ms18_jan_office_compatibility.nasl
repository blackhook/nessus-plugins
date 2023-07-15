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
  script_id(105695);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2018-0793",
    "CVE-2018-0794",
    "CVE-2018-0796",
    "CVE-2018-0797",
    "CVE-2018-0798",
    "CVE-2018-0801",
    "CVE-2018-0802",
    "CVE-2018-0804",
    "CVE-2018-0805",
    "CVE-2018-0806",
    "CVE-2018-0807",
    "CVE-2018-0812",
    "CVE-2018-0845",
    "CVE-2018-0848",
    "CVE-2018-0849",
    "CVE-2018-0862"
  );
  script_bugtraq_id(
    102347,
    102348,
    102370,
    102372,
    102373,
    102375,
    102406,
    102457,
    102459,
    102460,
    102461,
    102463
  );
  script_xref(name:"MSKB", value:"4011605");
  script_xref(name:"MSKB", value:"4011607");
  script_xref(name:"MSFT", value:"MS18-4011605");
  script_xref(name:"MSFT", value:"MS18-4011607");
  script_xref(name:"IAVA", value:"2018-A-0009-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Security Updates for Microsoft Office Compatibility SP3 (January 2018)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Compatibility Pack products installed
on the remote host are missing security updates.
It is, therefore, affected by multiple vulnerabilities :

- A remote code execution vulnerability exists in
  Microsoft Office software when the software fails to
  properly handle objects in memory. An attacker who
  successfully exploited the vulnerability could run
  arbitrary code in the context of the current user.
  (CVE-2018-0793, CVE-2018-0794, CVE-2018-0796, 
  CVE-2018-0798, CVE-2018-0801, CVE-2018-0802, 
  CVE-2018-0804, CVE-2018-0805, CVE-2018-0806, 
  CVE-2018-0807, CVE-2018-0812)

- An Office RTF remote code execution vulnerability 
  exists in Microsoft Office software when the Office 
  software fails to properly handle RTF files. An 
  attacker who successfully exploited the vulnerability 
  could run arbitrary code in the context of the current 
  user. (CVE-2018-0797)");
  # https://support.microsoft.com/en-us/help/4011605/descriptionofthesecurityupdateformicrosoftofficecompatibilitypackservi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d320dbde");
  # https://support.microsoft.com/en-us/help/4011607/description-of-the-security-update-for-microsoft-office-compatibility
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b248e04");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
    -KB4011605
    -KB4011607");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0862");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2023 Tenable Network Security, Inc.");

  script_dependencies("office_installed.nasl", "microsoft_office_compatibility_pack_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("misc_func.inc");
include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS18-01";
kbs = make_list(
  '4011605',
  '4011607'
);

vuln = FALSE;

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

######################################################################
 # Excel Compatibility pack
######################################################################
excel_compat_check = make_array(
    "12.0", make_array("version", "12.0.6784.5000", "kb", "4011605")
);

if (hotfix_check_office_product(product:"ExcelCnv",
                                display_name:"Office Compatibility Pack SP3",
                                checks:excel_compat_check,
                                bulletin:bulletin))
  vuln = TRUE;

####################################################################
#  Office Compatibility Pack
####################################################################
installs = get_kb_list("SMB/Office/WordCnv/*/ProductPath");
foreach install (keys(installs))
{
  path = installs[install];
  path = ereg_replace(pattern:'^(.+)\\\\[^\\\\]+\\.exe$', replace:"\1\", string:path, icase:TRUE);
  if(hotfix_check_fversion(path:path, file:"wordcnv.dll", version:"12.0.6784.5000", kb:"4011607", min_version:"12.0.0.0", product:"Microsoft Office Compatibility Pack") == HCF_OLDER)
  {
    vuln = TRUE;
    break;
  }
}

if(vuln)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
