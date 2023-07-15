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
  script_id(104558);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2017-11854", "CVE-2017-11877", "CVE-2017-11878");
  script_bugtraq_id(101746, 101747, 101756);
  script_xref(name:"MSKB", value:"4011265");
  script_xref(name:"MSKB", value:"4011205");
  script_xref(name:"MSFT", value:"MS17-4011265");
  script_xref(name:"MSFT", value:"MS17-4011205");
  script_xref(name:"IAVA", value:"2017-A-0337-S");

  script_name(english:"Security Updates for Microsoft Office Compatibility SP3 (November 2017)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Compatibility SP3 are missing security updates.
It is, therefore, affected by multiple vulnerabilities :

    - A remote code execution vulnerability exists in
    Microsoft Office software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2017-11854, CVE-2017-11878)

    - A security feature bypass vulnerability exists in
    Microsoft Office software by not enforcing macro
    settings on an Excel document. The security feature
    bypass by itself does not allow arbitrary code
    execution. To successfully exploit the vulnerability, an
    attacker would have to embed a control in an Excel
    worksheet that specifies a macro should be run.
    (CVE-2017-11877)");
  # https://support.microsoft.com/en-us/help/4011265/descriptionofthesecurityupdateformicrosoftofficecompatibilitypackservi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb28547f");
  # https://support.microsoft.com/en-us/help/4011205/descriptionofthesecurityupdateformicrosoftofficecompatibilitypackservi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bff36cbb");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV170020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f1b55d1");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
    -KB4011265
    -KB4011205");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11878");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS17-11";
kbs = make_list(
  '4011205',
  '4011265'
);

vuln = FALSE;

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

######################################################################
 # Excel Compatibility pack
######################################################################
excel_compat_check = make_array(
    "12.0", make_array("version", "12.0.6780.5000", "kb", "4011205")
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
  if(hotfix_check_fversion(path:path, file:"wordcnv.dll", version:"12.0.6780.5000", kb:"4011265", min_version:"12.0.0.0", product:"Microsoft Office Compatibility Pack") == HCF_OLDER)
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
