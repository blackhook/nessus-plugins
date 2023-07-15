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
  script_id(103133);
  script_version("1.14");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2017-8630",
    "CVE-2017-8676",
    "CVE-2017-8682",
    "CVE-2017-8695",
    "CVE-2017-8696",
    "CVE-2017-8742",
    "CVE-2017-8744"
  );
  script_bugtraq_id(
    100732,
    100741,
    100748,
    100755,
    100772,
    100773,
    100780
  );
  script_xref(name:"MSKB", value:"4011055");
  script_xref(name:"MSKB", value:"3213649");
  script_xref(name:"MSKB", value:"4011038");
  script_xref(name:"MSKB", value:"3213626");
  script_xref(name:"MSKB", value:"3213646");
  script_xref(name:"MSKB", value:"3213641");
  script_xref(name:"MSKB", value:"3213642");
  script_xref(name:"MSKB", value:"3213564");
  script_xref(name:"MSKB", value:"3203474");
  script_xref(name:"MSKB", value:"3213638");
  script_xref(name:"MSKB", value:"4011103");
  script_xref(name:"MSKB", value:"4011126");
  script_xref(name:"MSKB", value:"4011063");
  script_xref(name:"MSKB", value:"4011062");
  script_xref(name:"MSKB", value:"3213551");
  script_xref(name:"MSKB", value:"3213631");
  script_xref(name:"MSFT", value:"MS17-4011055");
  script_xref(name:"MSFT", value:"MS17-3213649");
  script_xref(name:"MSFT", value:"MS17-4011038");
  script_xref(name:"MSFT", value:"MS17-3213626");
  script_xref(name:"MSFT", value:"MS17-3213646");
  script_xref(name:"MSFT", value:"MS17-3213641");
  script_xref(name:"MSFT", value:"MS17-3213642");
  script_xref(name:"MSFT", value:"MS17-3213564");
  script_xref(name:"MSFT", value:"MS17-3203474");
  script_xref(name:"MSFT", value:"MS17-3213638");
  script_xref(name:"MSFT", value:"MS17-4011103");
  script_xref(name:"MSFT", value:"MS17-4011126");
  script_xref(name:"MSFT", value:"MS17-4011063");
  script_xref(name:"MSFT", value:"MS17-4011062");
  script_xref(name:"MSFT", value:"MS17-3213551");
  script_xref(name:"MSFT", value:"MS17-3213631");
  script_xref(name:"IAVA", value:"2017-A-0274");

  script_name(english:"Security Updates for Microsoft Office Products (September 2017)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates.
It is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists in
    Microsoft Office software when it fails to properly
    handle objects in memory. An attacker who successfully
    exploited the vulnerability could use a specially
    crafted file to perform actions in the security context
    of the current user. For example, the file could then
    take actions on behalf of the logged-on user with the
    same permissions as the current user. Exploitation of
    this vulnerability requires that a user open a specially
    crafted file with an affected version of Microsoft
    Office software. In an email attack scenario, an
    attacker could exploit the vulnerability by sending the
    specially crafted file to the user and convincing the
    user to open the file. In a web-based attack scenario,
    an attacker could host a website (or leverage a
    compromised website that accepts or hosts user-provided
    content) that contains a specially crafted file that is
    designed to exploit the vulnerability. However, an
    attacker would have no way to force the user to visit
    the website. Instead, an attacker would have to convince
    the user to click a link, typically by way of an
    enticement in an email or Instant Messenger message, and
    then convince the user to open the specially crafted
    file. The security update addresses the vulnerability by
    correcting how Microsoft Office handles files in memory.
    (CVE-2017-8630, CVE-2017-8744)

  - A remote code execution vulnerability exists when the
    Windows font library improperly handles specially
    crafted embedded fonts. An attacker who successfully
    exploited this vulnerability could take control of the
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights. Users whose accounts are
    configured to have fewer user rights on the system could
    be less impacted than users who operate with
    administrative user rights. There are multiple ways an
    attacker could exploit this vulnerability. In a web-
    based attack scenario, an attacker could host a
    specially crafted website that is designed to exploit
    this vulnerability and then convince a user to view the
    website. An attacker would have no way to force users to
    view the attacker-controlled content. Instead, an
    attacker would have to convince users to take action,
    typically by getting them to click a link in an email
    message or in an Instant Messenger message that takes
    users to the attacker's website, or by opening an
    attachment sent through email. In a file sharing attack
    scenario, an attacker could provide a specially crafted
    document file that is designed to exploit this
    vulnerability, and then convince a user to open the
    document file. The security update addresses the
    vulnerabilities by correcting how the Windows font
    library handles embedded fonts. (CVE-2017-8682)

  - An information disclosure vulnerability exists when
    Windows Uniscribe improperly discloses the contents of
    its memory. An attacker who successfully exploited the
    vulnerability could obtain information to further
    compromise the users system. There are multiple ways an
    attacker could exploit the vulnerability, such as by
    convincing a user to open a specially crafted document
    or by convincing a user to visit an untrusted webpage.
    The update addresses the vulnerability by correcting how
    Windows Uniscribe handles objects in memory.
    (CVE-2017-8695)

  - A remote code execution vulnerability exists due to the
    way Windows Uniscribe handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could take control of the affected system. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    Users whose accounts are configured to have fewer user
    rights on the system could be less impacted than users
    who operate with administrative user rights. There are
    multiple ways an attacker could exploit this
    vulnerability: In a web-based attack scenario, an
    attacker could host a specially crafted website designed
    to exploit this vulnerability and then convince a user
    to view the website. An attacker would have no way to
    force users to view the attacker-controlled content.
    Instead, an attacker would have to convince users to
    take action, typically by getting them to click a link
    in an email or instant message that takes users to the
    attacker's website, or by opening an attachment sent
    through email. In a file-sharing attack scenario, an
    attacker could provide a specially crafted document file
    designed to exploit this vulnerability and then convince
    a user to open the document file.The security update
    addresses the vulnerability by correcting how Windows
    Uniscribe handles objects in memory. (CVE-2017-8696)

  - A remote code execution vulnerability exists in
    Microsoft Office software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights. Users whose accounts are configured to have
    fewer user rights on the system could be less impacted
    than users who operate with administrative user rights.
    Exploitation of the vulnerability requires that a user
    open a specially crafted file with an affected version
    of Microsoft Office software. In an email attack
    scenario, an attacker could exploit the vulnerability by
    sending the specially crafted file to the user and
    convincing the user to open the file. In a web-based
    attack scenario, an attacker could host a website (or
    leverage a compromised website that accepts or hosts
    user-provided content) that contains a specially crafted
    file designed to exploit the vulnerability. An attacker
    would have no way to force users to visit the website.
    Instead, an attacker would have to convince users to
    click a link, typically by way of an enticement in an
    email or instant message, and then convince them to open
    the specially crafted file. Note that the Preview Pane
    is not an attack vector for this vulnerability. The
    security update addresses the vulnerability by
    correcting how Office handles objects in memory.
    (CVE-2017-8742)

  - An information disclosure vulnerability exists in the
    way that the Windows Graphics Device Interface (GDI)
    handles objects in memory, allowing an attacker to
    retrieve information from a targeted system. By itself,
    the information disclosure does not allow arbitrary code
    execution; however, it could allow arbitrary code to be
    run if the attacker uses it in combination with another
    vulnerability. To exploit this vulnerability, an
    attacker would have to log on to an affected system and
    run a specially crafted application. Note that where the
    severity is indicated as Critical in the Affected
    Products table, the Preview Pane is an attack vector for
    this vulnerability. The security update addresses the
    vulnerability by correcting how GDI handles memory
    addresses. (CVE-2017-8676)");
  # https://support.microsoft.com/en-us/help/4011055/descriptionofthesecurityupdateforoffice2010september12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8d24309b");
  # https://support.microsoft.com/en-us/help/3213649/descriptionofthesecurityupdatefor2007microsoftofficesuiteseptember12-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c95ea355");
  # https://support.microsoft.com/en-us/help/4011038/descriptionofthesecurityupdateforoffice2016september12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?69c44d41");
  # https://support.microsoft.com/en-us/help/3213626/descriptionofthesecurityupdateforoffice2010september12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?40a27f00");
  # https://support.microsoft.com/en-us/help/3213646/descriptionofthesecurityupdatefor2007microsoftofficesuiteseptember12-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a714c54e");
  # https://support.microsoft.com/en-us/help/3213641/descriptionofthesecurityupdatefor2007microsoftofficesuiteseptember12-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b84ca703");
  # https://support.microsoft.com/en-us/help/3213642/descriptionofthesecurityupdateforpowerpoint2007september12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?607de17a");
  # https://support.microsoft.com/en-us/help/3213564/descriptionofthesecurityupdateforoffice2013september12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f846aeb6");
  # https://support.microsoft.com/en-us/help/3203474/descriptionofthesecurityupdateforoffice2016september12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7601f27e");
  # https://support.microsoft.com/en-us/help/3213638/descriptionofthesecurityupdateforoffice2010september12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4928d07a");
  # https://support.microsoft.com/en-us/help/4011103/descriptionofthesecurityupdateforoffice2013september12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fa6bb9d8");
  # https://support.microsoft.com/en-us/help/4011126/descriptionofthesecurityupdateforoffice2016september12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d1e5263");
  # https://support.microsoft.com/en-us/help/4011063/descriptionofthesecurityupdatefor2007microsoftofficesuiteseptember12-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b27cd572");
  # https://support.microsoft.com/en-us/help/4011062/descriptionofthesecurityupdateforexcel2007september12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7194ec3f");
  # https://support.microsoft.com/en-us/help/3213551/descriptionofthesecurityupdateforoffice2016september12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ecdeba5");
  # https://support.microsoft.com/en-us/help/3213631/descriptionofthesecurityupdateforoffice2010september12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b2751aff");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft Office Products.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "microsoft_office_compatibility_pack_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = "MS17-09";
kbs = make_list(
  '3213641', # Office 2007 SP3
  '3213646', # Office 2007 SP3
  '3213649', # Office 2007 SP3
  '4011063', # Office 2007 SP3
  '3213626', # Office 2010 SP2
  '3213631', # Office 2010 SP2
  '3213638', # Office 2010 SP2
  '4011055', # Office 2010 SP2
  '3213564', # Office 2013 SP1
  '4011103', # Office 2013 SP1
  '3203474', # Office 2016
  '3213551', # Office 2016
  '4011038', # Office 2016
  '4011126'  # Office 2016
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();

office_vers = hotfix_check_office_version();

####################################################################
# Office 2007 SP3 Checks
####################################################################
if (office_vers["12.0"])
{
  office_sp = get_kb_item("SMB/Office/2007/SP");
  if (!isnull(office_sp) && office_sp == 3)
  {
    prod = "Microsoft Office 2007 SP3";
    common_path = hotfix_get_officecommonfilesdir(officever:"12.0");

    path = hotfix_append_path(
             path  : common_path,
             value : "\Microsoft Shared\TextConv"
    );
    if (hotfix_check_fversion(file:"Wpft632.cnv", version:"2006.1200.6776.5000", min_version:"2006.1200.0.0", path:path, kb:"3213646", bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_append_path(
      path  : common_path,
      value : "Microsoft Shared\Office12"
    );
    if (hotfix_check_fversion(file:"ogl.dll", version:"12.0.6776.5000", path:path, kb:"3213641", bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;
    if (hotfix_check_fversion(file:"mso.dll", version:"12.0.6777.5000", path:path, kb:"4011063", bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officeprogramfilesdir(officever:"12.0");
    if (hotfix_check_fversion(file:"usp10.dll", version:"1.626.6002.24173", path:path, kb:"3213649", bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;
  }
}

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
      value : "Microsoft Shared\Office14"
    );
    if (hotfix_check_fversion(file:"mso.dll", version:"14.0.7188.5002", path:path, kb:"4011055", bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;
    if (hotfix_check_fversion(file:"ogl.dll", version:"14.0.7188.5000", path:path, kb:"3213638", bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_append_path(
      path  : common_path,
      value : "\Microsoft Shared\TextConv"
    );
    if (hotfix_check_fversion(file:"Wpft632.cnv", version:"2010.1400.7188.5000", min_version:"2010.1400.0.0", path:path, kb:"3213626", bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officeprogramfilesdir(officever:"14.0");
    if (hotfix_check_fversion(file:"usp10.dll", version:"1.0626.7601.23883", path:path, kb:"3213631", bulletin:bulletin, product:prod) == HCF_OLDER)
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
      path  : hotfix_get_officecommonfilesdir(officever:"15.0"),
      value : "Microsoft Shared\Office15"
    );
    if (hotfix_check_fversion(file:"mso.dll", version:"15.0.4963.1002", path:path, kb:"4011103", bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_append_path(
      path  : common_path,
      value : "\Microsoft Shared\TextConv"
    );
    if (hotfix_check_fversion(file:"Wpft632.cnv", version:"2012.1500.4963.1000", min_version:"2012.1500.0.0", path:path, kb:"3213564", bulletin:bulletin, product:prod) == HCF_OLDER)
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
      value : "Microsoft Shared\Office16"
    );
    kb   = "4011038";
    file = "mso99lwin32client.dll";
    if (
      hotfix_check_fversion(file:file, version:"16.0.4588.1000", channel:"MSI", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:file, version:"16.0.7726.1057", channel:"Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:file, version:"16.0.8201.2193", channel:"Deferred", channel_version:"1705", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:file, version:"16.0.8431.2079", channel:"First Release for Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:file, version:"16.0.8326.2107", channel:"Current", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER
    )
      vuln = TRUE;

    kb   = "4011126";
    file = "mso30win32client.dll";
    if (
      hotfix_check_fversion(file:file, version:"16.0.4588.1002", channel:"MSI", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:file, version:"16.0.7726.1057", channel:"Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:file, version:"16.0.8201.2193", channel:"Deferred", channel_version:"1705", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:file, version:"16.0.8431.2079", channel:"First Release for Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:file, version:"16.0.8326.2107", channel:"Current", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER
    )
      vuln = TRUE;

    kb   = "3213551";
    file = "wpft632.cnv";
    path = hotfix_append_path(
      path  : common_path,
      value : "Microsoft Shared\TextConv"
    );
    if (
      hotfix_check_fversion(file:file, version:"2012.1600.4588.1000", min_version:"2012.1600.0.0", channel:"MSI", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:file, version:"2012.1600.7726.1057", min_version:"2012.1600.0.0", channel:"Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:file, version:"2012.1600.8201.2193", min_version:"2012.1600.0.0", channel:"Deferred", channel_version:"1705", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:file, version:"2012.1600.8431.2079", min_version:"2012.1600.0.0", channel:"First Release for Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:file, version:"2012.1600.8326.2107", min_version:"2012.1600.0.0", channel:"Current", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER
    )
      vuln = TRUE;

    path = hotfix_get_officeprogramfilesdir(officever:"16.0");
    kb   = "3203474";
    file = "igx.dll";
    if (
      hotfix_check_fversion(file:file, version:"16.0.4588.1000", channel:"MSI", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:file, version:"16.0.7726.1057", channel:"Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:file, version:"16.0.8201.2193", channel:"Deferred", channel_version:"1705", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:file, version:"16.0.8431.2079", channel:"First Release for Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:file, version:"16.0.8326.2107", channel:"Current", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER
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
