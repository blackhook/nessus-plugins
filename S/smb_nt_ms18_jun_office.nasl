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
  script_id(110495);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-8246", "CVE-2018-8248");
  script_xref(name:"MSKB", value:"4022182");
  script_xref(name:"MSKB", value:"3115197");
  script_xref(name:"MSKB", value:"3115248");
  script_xref(name:"MSKB", value:"4022177");
  script_xref(name:"MSKB", value:"4018387");
  script_xref(name:"MSKB", value:"4022199");
  script_xref(name:"MSFT", value:"MS18-4022182");
  script_xref(name:"MSFT", value:"MS18-3115197");
  script_xref(name:"MSFT", value:"MS18-3115248");
  script_xref(name:"MSFT", value:"MS18-4022177");
  script_xref(name:"MSFT", value:"MS18-4018387");
  script_xref(name:"MSFT", value:"MS18-4022199");

  script_name(english:"Security Updates for Microsoft Office Products (June 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates.
It is, therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists when
    Microsoft Excel improperly discloses the contents of its
    memory. An attacker who exploited the vulnerability
    could use the information to compromise the users
    computer or data.  (CVE-2018-8246)

  - A remote code execution vulnerability exists in
    Microsoft Excel software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2018-8248)");
  # https://support.microsoft.com/en-us/help/4022182/description-of-the-security-update-for-office-2013-june-12-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a8eb3689");
  # https://support.microsoft.com/en-us/help/3115197/description-of-the-security-update-for-office-2010-june-12-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b564abea");
  # https://support.microsoft.com/en-us/help/3115248/description-of-the-security-update-for-office-2010-june-12-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bace5ce1");
  # https://support.microsoft.com/en-us/help/4022177/description-of-the-security-update-for-office-2016-june-12-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3af47e5f");
  # https://support.microsoft.com/en-us/help/4018387/description-of-the-security-update-for-office-2013-june-12-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?abfa03eb");
  # https://support.microsoft.com/en-us/help/4022199/description-of-the-security-update-for-office-2010-june-12-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3d3bb130");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4022182
  -KB3115197
  -KB3115248
  -KB4022177
  -KB4018387
  -KB4022199");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8248");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/12");

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

bulletin = "MS18-06";
kbs = make_list(
  '3115197', # Office 2010 SP2
  '3115248', # Office 2010 SP2
  '4022199', # Office 2010 SP2
  '4018387', # Office 2013 SP1
  '4022182', # Office 2013 SP1
  '4022177'  # Office 2016
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
  ####################################################################
  if (office_vers["14.0"])
  {
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (!isnull(office_sp) && office_sp == 2)
    {
      prod = "Microsoft Office 2010 SP2";

      path = hotfix_get_officeprogramfilesdir(officever:"14.0");

      path = hotfix_append_path(
        path  : path,
        value : "Microsoft Office\Office14"
      );
      if (hotfix_check_fversion(file:"oart.dll", version:"14.0.7210.5000", path:path, kb:"3115197", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;

      # same path as above
      if (hotfix_check_fversion(file:"oartconv.dll", version:"14.0.7210.5000", path:path, kb:"3115248", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;

      # same path as above
      if (hotfix_check_fversion(file:"graph.exe", version:"14.0.7210.5000", path:path, kb:"4022199", bulletin:bulletin, product:prod) == HCF_OLDER)
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
      if (hotfix_check_fversion(file:"oart.dll", version:"15.0.5041.1000", path:path, kb:"4018387", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;

      # same path as above
      if (hotfix_check_fversion(file:"graph.exe", version:"15.0.5041.1000", path:path, kb:"4022182", bulletin:bulletin, product:prod) == HCF_OLDER)
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

      path = hotfix_get_officeprogramfilesdir(officever:"16.0");
      msi_path = hotfix_append_path(path: path, value : "Microsoft Office\Office16");
      c2r_path = hotfix_append_path(path: path, value : "Microsoft Office\root\Office16");
      file = "graph.exe";
      kb = "4022177";
      if (
        hotfix_check_fversion(file:file, version:"16.0.4705.1000", channel:"MSI", channel_product:"Office", path:msi_path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.8201.2278", channel:"Deferred", channel_product:"Office", path:c2r_path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.8431.2270", channel:"Deferred", channel_version:"1708", channel_product:"Office", path:c2r_path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.9126.2227", channel:"First Release for Deferred", channel_product:"Office", path:c2r_path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.9330.2118", channel:"Current", channel_product:"Office", path:c2r_path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER
      )
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
