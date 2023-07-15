#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103784);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/17");

  script_cve_id("CVE-2017-11825", "CVE-2017-11826");
  script_bugtraq_id(101124, 101219);
  script_xref(name:"MSKB", value:"3172524");
  script_xref(name:"MSKB", value:"3172531");
  script_xref(name:"MSKB", value:"4011185");
  script_xref(name:"MSKB", value:"2920723");
  script_xref(name:"MSKB", value:"2553338");
  script_xref(name:"MSKB", value:"2837599");
  script_xref(name:"MSKB", value:"4011222");
  script_xref(name:"MSKB", value:"3213648");
  script_xref(name:"MSKB", value:"4011232");
  script_xref(name:"MSKB", value:"3213630");
  script_xref(name:"MSKB", value:"3213627");
  script_xref(name:"MSFT", value:"MS17-3172524");
  script_xref(name:"MSFT", value:"MS17-3172531");
  script_xref(name:"MSFT", value:"MS17-4011185");
  script_xref(name:"MSFT", value:"MS17-2920723");
  script_xref(name:"MSFT", value:"MS17-2553338");
  script_xref(name:"MSFT", value:"MS17-2837599");
  script_xref(name:"MSFT", value:"MS17-4011222");
  script_xref(name:"MSFT", value:"MS17-3213648");
  script_xref(name:"MSFT", value:"MS17-4011232");
  script_xref(name:"MSFT", value:"MS17-32136304");
  script_xref(name:"MSFT", value:"MS17-3213627");
  script_xref(name:"IAVA", value:"2017-A-0291-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"Security Updates for Microsoft Office Products (October 2017)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates.
It is, therefore, affected by multiple vulnerabilities :

  - Microsoft has released an update for Microsoft Office that
    provides enhanced security as a defense-in-depth measure.

  - A remote code execution vulnerability exists in Microsoft Office
    software when it fails to properly handle objects in memory. An
    attacker who successfully exploited the vulnerability could use a
    specially crafted file to perform actions in the security context
    of the current user. For example, the file could then take actions
    on behalf of the logged-on user with the same permissions as the
    current user. (CVE-2017-11825)

  - A remote code execution vulnerability exists in Microsoft Office
    software when the software fails to properly handle objects in
    memory. An attacker who successfully exploited the vulnerability
    could run arbitrary code in the context of the current user. If
    the current user is logged on with administrative user rights, an
    attacker could take control of the affected system. An attacker
    could then install programs; view, change, or delete data; or
    create new accounts with full user rights. Users whose accounts
    are configured to have fewer user rights on the system could be
    less impacted than users who operate with administrative user
    rights. (CVE-2017-11826)");
  # https://support.microsoft.com/en-us/help/2553338/description-of-the-security-update-for-office-2010-october-10-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a8a017c7");
  # https://support.microsoft.com/en-us/help/2837599/description-of-the-security-update-for-office-2010-october-10-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6c08bcd5");
  # https://support.microsoft.com/en-us/help/3172524/description-of-the-security-update-for-office-2013-october-10-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4720201");
  # https://support.microsoft.com/en-us/help/3172531/description-of-the-security-update-for-office-2013-october-10-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e43bd8f6");
  # https://support.microsoft.com/en-us/help/4011185/descriptionofthesecurityupdateforoffice2016october10-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3fd7628b");
  # https://support.microsoft.com/en-us/help/2920723/description-of-the-security-update-for-office-2016-october-10-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3c605abc");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/office/mt465751");
  # https://support.microsoft.com/en-us/help/4011222/description-of-the-security-update-for-word-2016-october-10-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?544bebd5");
  # https://support.microsoft.com/en-us/help/3213648/description-of-the-security-update-for-word-2007-october-10-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?005e6964");
  # https://support.microsoft.com/en-us/help/4011232/description-of-the-security-update-for-word-2013-october-10-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d96e89f");
  # https://support.microsoft.com/en-us/help/3213630/description-of-the-security-update-for-word-2010-october-10-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e757244");
  # https://support.microsoft.com/en-us/help/3213627/description-of-the-security-update-for-office-2010-october-10-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e7317f0");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft Office Products.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11826");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS17-10";
kbs = make_list(
  '2553338', # Office 2010 SP2
  '2837599', # Office 2010 SP2
  '3172524', # Office 2013 SP1
  '3172531', # Office 2013 SP1
  '4011185', # Office 2016
  '2920723', # Office 2016
  '3213648', # Word 2007 SP3
  '3213630', # Word 2010 SP2
  '3213627', # Word 2010 SP2
  '4011232', # Word 2013 SP1
  '4011222'  # Word 2016
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();

######################################################################
# Office 2007, 2010, 2013, 2016
######################################################################
function perform_office_checks()
{
  local_var office_vers, office_sp, common_path, path, prod, file, kb;
  office_vers = hotfix_check_office_version();

  ####################################################################
  # Office 2010 SP2 Checks
  ####################################################################
  if (office_vers["14.0"])
  {
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (!isnull(office_sp) && office_sp == 2)
    {
      prod = "Microsoft Office 2010 SP2";
      common_path = hotfix_get_officecommonfilesdir(officever:"14.0");

      path = hotfix_append_path(
        path  : common_path,
        value : "Microsoft Shared\Source Engine"
      );
      if (hotfix_check_fversion(file:"ose.exe", version:"14.0.7189.5000", path:path, kb:"2553338", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;

      path = hotfix_append_path(
        path  : common_path,
        value : "Microsoft Shared\OFFICE14\Office Setup Controller"
      );
      if (hotfix_check_fversion(file:"osetup.dll", version:"14.0.7189.5000", path:path, kb:"2837599", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;
    }
  }

  ####################################################################
  # Office 2013 SP1 Checks
  ####################################################################
  if (office_vers["15.0"])
  {
    office_sp = get_kb_item("SMB/Office/2013/SP");
    if (!isnull(office_sp) && office_sp == 1)
    {
      prod = "Microsoft Office 2013 SP1";
      common_path = hotfix_get_officecommonfilesdir(officever:"15.0");

      path = hotfix_append_path(
        path  : common_path,
        value : "Microsoft Shared\Source Engine"
      );
      if (hotfix_check_fversion(file:"ose.exe", version:"15.0.4971.1000", path:path, kb:"3172524", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;

      path = hotfix_append_path(
        path  : common_path,
        value : "Microsoft Shared\OFFICE15\Office Setup Controller"
      );
      if (hotfix_check_fversion(file:"osetup.dll", version:"15.0.4971.1000", path:path, kb:"3172531", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;
    }
  }

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
        value : "Microsoft Shared\Source Engine"
      );
      kb   = "4011185";
      file = "ose.exe";
      if (
        hotfix_check_fversion(file:file, version:"16.0.4600.1000", channel:"MSI", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.7726.1059", channel:"Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.8201.2200", channel:"Deferred", channel_version:"1705", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.8431.2107", channel:"First Release for Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.8431.2107", channel:"Current", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER
      )
        vuln = TRUE;

      # no update channels seem to have this file, only the MSI installer variant has it
      path = hotfix_append_path(
        path  : common_path,
        value : "Microsoft Shared\OFFICE16\Office Setup Controller"
      );
      kb   = "2920723";
      file = "osetup.dll";
      if (
        hotfix_check_fversion(file:file, version:"16.0.4600.1000", channel:"MSI", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER
      )
        vuln = TRUE;
    }
  }
}

######################################################################
# Word 2007, 2010, 2013, 2016
######################################################################
function perform_word_checks()
{
  local_var word_checks, kb16;

  kb16 = "4011222";
  word_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6779.5000", "kb", "3213648"),
    "14.0", make_array("sp", 2, "version", "14.0.7189.5001", "kb", "3213630"),
    "15.0", make_array("sp", 1, "version", "15.0.4971.1002", "kb", "4011232"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4600.1002", "channel", "MSI", "kb", kb16),
      make_array("sp", 0, "version", "16.0.7766.2119", "channel", "Deferred", "kb", kb16),
      make_array("sp", 0, "version", "16.0.8201.2200", "channel", "Deferred", "channel_version", "1705", "kb", kb16),
      make_array("sp", 0, "version", "16.0.8431.2107", "channel", "First Release for Deferred", "kb", kb16),
      make_array("sp", 0, "version", "16.0.8431.2107", "channel", "Current", "kb", kb16)
    )
  );
  if (hotfix_check_office_product(product:"Word", checks:word_checks, bulletin:bulletin))
    vuln = TRUE;
}

######################################################################
# MAIN
######################################################################
perform_office_checks();
perform_word_checks();

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
