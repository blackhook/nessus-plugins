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
  script_id(117458);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id("CVE-2018-8332");

  script_name(english:"Security Updates for Microsoft Office Products (September 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates.
They are, therefore, affected by a vulnerability :

  - A remote code execution vulnerability exists when the
    Windows font library improperly handles specially crafted
    embedded fonts. An attacker who successfully exploited this
    vulnerability could take control of the affected system. An
    attacker could then install programs; view, change, or delete
    data; or create new accounts with full user rights. Users
    whose accounts are configured to have fewer user rights on
    the system could be less impacted than users who operate with
    administrative user rights. (CVE-2018-8332)");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8332
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9373baa3");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a security update to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8332");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");

global_var vuln;

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS18-09";

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();

office_vers = hotfix_check_office_version();

####################################################################
# Office 2016 Checks
####################################################################
if (office_vers["16.0"])
{
  office_sp = get_kb_item("SMB/Office/2016/SP");
  if (!isnull(office_sp) && office_sp == 0)
  {
    prod = "Microsoft Office 2016";

    common_path = hotfix_get_officecommonfilesdir(officever:"16.0");
    path = hotfix_append_path(
      path  : common_path,
      value : "Microsoft Shared\OFFICE16"
    );
    file = "mso.dll";
    if (
      hotfix_check_fversion(file:file, version:"16.0.8431.2309", channel:"Deferred", channel_product:"Office", path:path, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:file, version:"16.0.9126.2282", channel:"Deferred", channel_version:"1803", channel_product:"Office", path:path, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:file, version:"16.0.10730.20102", channel:"First Release for Deferred", channel_product:"Office", path:path, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:file, version:"16.0.10730.20102", channel:"Current", channel_product:"Office", path:path, bulletin:bulletin, product:prod) == HCF_OLDER
    )
      vuln = TRUE;
  }
}

if (vuln)
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
