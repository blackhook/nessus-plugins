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
  script_id(109614);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/11");

  script_cve_id(
    "CVE-2018-8147",
    "CVE-2018-8148",
    "CVE-2018-8150",
    "CVE-2018-8157",
    "CVE-2018-8158",
    "CVE-2018-8160",
    "CVE-2018-8161",
    "CVE-2018-8173"
  );
  script_xref(name:"MSKB", value:"4022137");
  script_xref(name:"MSKB", value:"2899590");
  script_xref(name:"MSKB", value:"3172436");
  script_xref(name:"MSKB", value:"4022139");
  script_xref(name:"MSKB", value:"3162075");
  script_xref(name:"MSKB", value:"4018327");
  script_xref(name:"MSFT", value:"MS18-4022137");
  script_xref(name:"MSFT", value:"MS18-2899590");
  script_xref(name:"MSFT", value:"MS18-3172436");
  script_xref(name:"MSFT", value:"MS18-4022139");
  script_xref(name:"MSFT", value:"MS18-3162075");
  script_xref(name:"MSFT", value:"MS18-4018327");
  script_xref(name:"IAVA", value:"2018-A-0151-S");

  script_name(english:"Security Updates for Microsoft Office Products (May 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates.
It is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists in
    Microsoft Excel software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2018-8147, CVE-2018-8148)

  - An information disclosure vulnerability exists in
    Outlook when a message is opened. This vulnerability
    could potentially result in the disclosure of sensitive
    information to a malicious site.  (CVE-2018-8160)

  - A remote code execution vulnerability exists in
    Microsoft Office software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2018-8157, CVE-2018-8158,
    CVE-2018-8161)

  - A remote code execution vulnerability exists in
    Microsoft InfoPath when the software fails to properly
    handle objects in memory. An attacker who successfully
    exploited the vulnerability could run arbitrary code in
    the context of the current user. If the current user is
    logged on with administrative user rights, an attacker
    could take control of the affected system. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    (CVE-2018-8173)

  - A security feature bypass vulnerability exists when the
    Microsoft Outlook attachment block filter does not
    properly handle attachments. An attacker who successfully
    exploited the vulnerability could execute arbitrary
    commands. The security feature bypass by itself does not
    allow arbitrary code execution. (CVE-2018-8150)");
  # https://support.microsoft.com/en-us/help/4022137/description-of-the-security-update-for-office-2010-may-8-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf18707b");
  # https://support.microsoft.com/en-us/help/2899590/description-of-the-security-update-for-office-2010-may-8-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0637e574");
  # https://support.microsoft.com/en-us/help/3172436/description-of-the-security-update-for-office-2013-may-8-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d461f35a");
  # https://support.microsoft.com/en-us/help/4022139/description-of-the-security-update-for-office-2010-may-8-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b26dcaa");
  # https://support.microsoft.com/en-us/help/3162075/description-of-the-security-update-for-infopath-2013-may-8-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c093035");
  # https://support.microsoft.com/en-us/help/4018327/description-of-the-security-update-for-office-2016-may-8-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5738c42");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4022137
  -KB2899590
  -KB3172436
  -KB4022139
  -KB3162075
  -KB4018327");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8173");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS18-05";
kbs = make_list(
  '2899590', # Office 2010 SP2
  '4022137', # Office 2010 SP2
  '4022139', # Office 2010 SP2
  '3172436', # Office 2013 SP1
  '3162075', # Office 2013 SP1
  '4018327'  # Office 2016
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();

######################################################################
# Office 2010, 2013, 2016
######################################################################
function perform_office_checks()
{
  local_var office_vers, office_sp, common_path, path, prod, file, kb, c2r_file, infopath_prod, msi_path, c2r_path, checks;
  office_vers = hotfix_check_office_version();

  ####################################################################
  # Office 2010 SP2 Checks
  # wwlibcxm.dll only exists if KB2428677 is installed
  ####################################################################
  if (office_vers["14.0"])
  {
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (!isnull(office_sp) && office_sp == 2)
    {
      prod = "Microsoft Office 2010 SP2";

      path = hotfix_get_officeprogramfilesdir(officever:"14.0");

      if (hotfix_check_fversion(file:"wwlibcxm.dll", version:"14.0.7208.5000", path:path, kb:"4022139", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;

      path = hotfix_append_path(
        path  : path,
        value : "Microsoft Office\Office14"
      );
      if (hotfix_check_fversion(file:"graph.exe", version:"14.0.7208.5000", path:path, kb:"2899590", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;

      path = hotfix_get_officecommonfilesdir(officever:"14.0");
      path = hotfix_append_path(
        path  : path,
        value : "Microsoft Shared\Office14"
      );
      if (hotfix_check_fversion(file:"mso.dll", version:"14.0.7208.5000", path:path, kb:"4022137", bulletin:bulletin, product:prod) == HCF_OLDER)
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

      path = hotfix_get_officeprogramfilesdir(officever:"15.0");
      path = hotfix_append_path(
        path  : path,
        value : "Microsoft Office\Office15"
      );
      if (hotfix_check_fversion(file:"graph.exe", version:"15.0.5031.1000", path:path, kb:"3172436", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;

      # InfoPath 2013
      infopath_prod = "Microsoft InfoPath 2013 SP1";
      if(max_index(keys(get_kb_list("SMB/Office/InfoPath/15.0*/ProductPath"))) > 0)
      {
        if (hotfix_check_fversion(file:"ipeditor.dll", version:"15.0.5027.1000", path:path, kb:"3162075", bulletin:bulletin, product:infopath_prod) == HCF_OLDER)
          vuln = TRUE;
      }
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

      path = hotfix_get_officeprogramfilesdir(officever:"16.0");
      msi_path = hotfix_append_path(path: path, value : "Microsoft Office\Office16");
      c2r_path = hotfix_append_path(path: path, value : "Microsoft Office\root\Office16");
      file = "graph.exe";
      kb = "4018327";
      if (
        hotfix_check_fversion(file:file, version:"16.0.4690.1000", channel:"MSI", channel_product:"Office", path:msi_path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.8201.2278", channel:"Deferred", channel_product:"Office", path:c2r_path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.8431.2250", channel:"Deferred", channel_version:"1708", channel_product:"Office", path:c2r_path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.9126.2191", channel:"First Release for Deferred", channel_product:"Office", path:c2r_path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.9226.2126", channel:"Current", channel_product:"Office", path:c2r_path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER
      )
        vuln = TRUE;

      # Outlook 2016 C2R only update
      checks = make_array(
        "16.0", make_nested_list(
          make_array("version", "16.0.8201.2278", "channel", "Deferred"), # Deferred
          make_array("version", "16.0.8431.2250", "channel", "Deferred", "channel_version", "1708"), # Semi-Annual
          make_array("version", "16.0.9126.2191", "channel", "First Release for Deferred"), # Targeted
          make_array("version", "16.0.9226.2126", "channel", "Current") # Monthly
        )
      );
      if (hotfix_check_office_product(product:"Outlook", checks:checks, bulletin:bulletin))
        vuln = TRUE;
    }
  }
}

######################################################################
# MAIN
######################################################################
perform_office_checks();

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
