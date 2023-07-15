#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(100782);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/17");

  script_cve_id(
    "CVE-2017-0260",
    "CVE-2017-0282",
    "CVE-2017-0283",
    "CVE-2017-0284",
    "CVE-2017-0285",
    "CVE-2017-0286",
    "CVE-2017-0287",
    "CVE-2017-0288",
    "CVE-2017-0289",
    "CVE-2017-0292",
    "CVE-2017-8506",
    "CVE-2017-8507",
    "CVE-2017-8508",
    "CVE-2017-8509",
    "CVE-2017-8510",
    "CVE-2017-8511",
    "CVE-2017-8512",
    "CVE-2017-8513",
    "CVE-2017-8527",
    "CVE-2017-8528",
    "CVE-2017-8531",
    "CVE-2017-8532",
    "CVE-2017-8533",
    "CVE-2017-8534",
    "CVE-2017-8550"
  );
  script_bugtraq_id(
    98810,
    98811,
    98812,
    98813,
    98815,
    98816,
    98819,
    98820,
    98821,
    98822,
    98827,
    98828,
    98830,
    98836,
    98885,
    98891,
    98914,
    98916,
    98918,
    98920,
    98922,
    98923,
    98929,
    98933,
    98949
  );
  script_xref(name:"MSKB", value:"3118304");
  script_xref(name:"MSKB", value:"3118389");
  script_xref(name:"MSKB", value:"3127888");
  script_xref(name:"MSKB", value:"3162051");
  script_xref(name:"MSKB", value:"3178667");
  script_xref(name:"MSKB", value:"3191828");
  script_xref(name:"MSKB", value:"3191837");
  script_xref(name:"MSKB", value:"3191844");
  script_xref(name:"MSKB", value:"3191848");
  script_xref(name:"MSKB", value:"3191882");
  script_xref(name:"MSKB", value:"3191898");
  script_xref(name:"MSKB", value:"3191908");
  script_xref(name:"MSKB", value:"3191932");
  script_xref(name:"MSKB", value:"3191938");
  script_xref(name:"MSKB", value:"3191943");
  script_xref(name:"MSKB", value:"3191944");
  script_xref(name:"MSKB", value:"3191945");
  script_xref(name:"MSKB", value:"3203383");
  script_xref(name:"MSKB", value:"3203386");
  script_xref(name:"MSKB", value:"3203392");
  script_xref(name:"MSKB", value:"3203393");
  script_xref(name:"MSKB", value:"3203427");
  script_xref(name:"MSKB", value:"3203436");
  script_xref(name:"MSKB", value:"3203438");
  script_xref(name:"MSKB", value:"3203441");
  script_xref(name:"MSKB", value:"3203460");
  script_xref(name:"MSKB", value:"3203461");
  script_xref(name:"MSKB", value:"3203463");
  script_xref(name:"MSKB", value:"3203464");
  script_xref(name:"MSKB", value:"3203467");
  script_xref(name:"MSKB", value:"3203484");
  script_xref(name:"MSFT", value:"MS17-3118304");
  script_xref(name:"MSFT", value:"MS17-3118389");
  script_xref(name:"MSFT", value:"MS17-3127888");
  script_xref(name:"MSFT", value:"MS17-3162051");
  script_xref(name:"MSFT", value:"MS17-3178667");
  script_xref(name:"MSFT", value:"MS17-3191828");
  script_xref(name:"MSFT", value:"MS17-3191837");
  script_xref(name:"MSFT", value:"MS17-3191844");
  script_xref(name:"MSFT", value:"MS17-3191848");
  script_xref(name:"MSFT", value:"MS17-3191882");
  script_xref(name:"MSFT", value:"MS17-3191898");
  script_xref(name:"MSFT", value:"MS17-3191908");
  script_xref(name:"MSFT", value:"MS17-3191932");
  script_xref(name:"MSFT", value:"MS17-3191938");
  script_xref(name:"MSFT", value:"MS17-3191943");
  script_xref(name:"MSFT", value:"MS17-3191944");
  script_xref(name:"MSFT", value:"MS17-3191945");
  script_xref(name:"MSFT", value:"MS17-3203383");
  script_xref(name:"MSFT", value:"MS17-3203386");
  script_xref(name:"MSFT", value:"MS17-3203392");
  script_xref(name:"MSFT", value:"MS17-3203393");
  script_xref(name:"MSFT", value:"MS17-3203427");
  script_xref(name:"MSFT", value:"MS17-3203436");
  script_xref(name:"MSFT", value:"MS17-3203438");
  script_xref(name:"MSFT", value:"MS17-3203441");
  script_xref(name:"MSFT", value:"MS17-3203460");
  script_xref(name:"MSFT", value:"MS17-3203461");
  script_xref(name:"MSFT", value:"MS17-3203463");
  script_xref(name:"MSFT", value:"MS17-3203464");
  script_xref(name:"MSFT", value:"MS17-3203467");
  script_xref(name:"MSFT", value:"MS17-3203484");
  script_xref(name:"IAVA", value:"2017-A-0179-S");

  script_name(english:"Security Update for Microsoft Office Products (June 2017)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office application installed on the remote Windows host
is missing a security update. It is, therefore, affected by multiple
vulnerabilities :

  - Multiple remote code execution vulnerabilities exist in
    Microsoft Office due to improper validation of input
    before loading dynamic link library (DLL) files. An
    unauthenticated, remote attacker can exploit these, by
    convincing a user to open a specially crafted Office
    document, to execute arbitrary code in the context of
    the current user. (CVE-2017-0260. CVE-2017-8506)

  - Multiple information disclosure vulnerabilities exist in
    Windows Uniscribe due to improper handling of objects in
    memory. An unauthenticated, remote attacker can exploit
    these, by convincing a user to visit a specially crafted
    website or to open a specially crafted document file, to
    disclose the contents of memory. (CVE-2017-0282,
    CVE-2017-0284, CVE-2017-0285, CVE-2017-8534)

  - Multiple remote code execution vulnerabilities exist in
    Windows Uniscribe due to improper handling of objects in
    memory. An unauthenticated, remote attacker can exploit
    these, by convincing a user to visit a specially crafted
    website or open a specially crafted document, to execute
    arbitrary code in the context of the current user.
    (CVE-2017-0283, CVE-2017-8528)

  - Multiple information disclosure vulnerabilities exist in
    the Windows GDI component due to improper handling of
    objects in memory. An unauthenticated, remote attacker
    can exploit these, by convincing a user to visit a
    specially crafted website or to open a specially crafted
    document file, to disclose the contents of memory.
    (CVE-2017-0286, CVE-2017-0287, CVE-2017-0288,
    CVE-2017-0289, CVE-2017-8531, CVE-2017-8532,
    CVE-2017-8533)

  - A remote code execution vulnerability exists in
    Microsoft Windows due to improper parsing of PDF files.
    An unauthenticated, remote attacker can exploit this, by
    convincing a user to open a specially crafted PDF file,
    to execute arbitrary code in the context of the current
    user. (CVE-2017-0292)

  - A remote code execution vulnerability exists in
    Microsoft Outlook due to improper parsing of email
    messages. An unauthenticated, remote attacker can
    exploit this, by convincing a user to open a specially
    crafted email message, to execute arbitrary code in the
    context of the current user. (CVE-2017-8507)

  - A security bypass vulnerability exists in Microsoft
    Outlook due to improper parsing of file formats. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to open a specially crafted Office
    document, to bypass security feature protections.
    (CVE-2017-8508)

  - Multiple remote code execution vulnerabilities exist in
    Microsoft Office due to improper handling of objects in
    memory. An unauthenticated, remote attacker can exploit
    these, by convincing a user to open a specially crafted
    Office document, to execute arbitrary code in the
    context of the current user. (CVE-2017-8509,
    CVE-2017-8510, CVE-2017-8511, CVE-2017-8512,
    CVE-2017-8550)

  - A remote code execution vulnerability exists in
    Microsoft PowerPoint due to improper handling of objects
    in memory. An unauthenticated, remote attacker can
    exploit this, by convincing a user to open a specially
    crafted file, to execute arbitrary code in the context
    of the current user. (CVE-2017-8513)

  - A remote code execution vulnerability exists in the
    Windows font library due to improper handling of
    embedded fonts. An unauthenticated, remote attacker can
    exploit this, by convincing a user to visit a specially
    crafted website or open a specially crafted Microsoft
    document, to execute arbitrary code in the context of
    the current user. (CVE-2017-8527)");
  script_set_attribute(attribute:"see_also", value:"https://portal.msrc.microsoft.com/en-us/security-guidance/summary");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Office 2007,
2010, 2013, and 2016; Microsoft OneNote 2010; Microsoft Outlook 2007,
2010, and 2016; Microsoft PowerPoint 2007; Microsoft Word 2007, 2010,
2013, and 2016; Microsoft Word Viewer; and Microsoft Office
Compatibility Pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:onenote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "onenote_installed.nbin", "microsoft_office_compatibility_pack_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = "MS17-06";
kbs = make_list(
  '3118304', # Office 2007 SP3
  '3118389', # Office 2010 SP2
  '3127888', # PowerPoint 2007 SP3
  '3162051', # Office 2013 SP1
  '3178667', # Office 2016
  '3191828', # Office 2007 SP3
  '3191837', # Office 2007 SP3
  '3191844', # Office 2010 SP2
  '3191848', # Office 2010 SP2
  '3191882', # Office 2016
  '3191898', # Outlook 2007 SP3
  '3191908', # OneNote 2010 SP2
  '3191932', # Outlook 2016
  '3191938', # Outlook 2013 SP1
  '3191943', # Office 2016
  '3191944', # Office 2016
  '3191945', # Word 2016
  '3203383', # Office 2016
  '3203386', # Office 2013 SP1
  '3203392', # Office 2013 SP1
  '3203393', # Word 2013 SP1
  '3203427', # Office Word Viewer
  '3203436', # Office 2007 SP3
  '3203438', # Office Compatibility Pack SP3
  '3203441', # Word 2007 SP3
  '3203460', # Office 2010 SP2
  '3203461', # Office 2010 SP2
  '3203463', # Office 2010 SP2
  '3203464', # Word 2010 SP2
  '3203467', # Outlook 2010 SP2
  '3203484'  # Office Word Viewer
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
               value : "\Microsoft Shared\GRPHFLT"
      );
      if (hotfix_check_fversion(file:"pictim32.flt", version:"2006.1200.6769.5000", min_version:"2006.1200.0.0", path:path, kb:"3118304", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;

      path = hotfix_append_path(
        path  : common_path,
        value : "Microsoft Shared\Office12"
      );
      if (hotfix_check_fversion(file:"ogl.dll", version:"12.0.6769.5000", path:path, kb:"3191828", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;
      if (hotfix_check_fversion(file:"mso.dll", version:"12.0.6770.5000", path:path, kb:"3203436", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;

      path = hotfix_get_officeprogramfilesdir(officever:"12.0");
      if (hotfix_check_fversion(file:"usp10.dll", version:"1.626.6002.24099", path:path, kb:"3191837", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;
    }
  }

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
      common_path = hotfix_get_officecommonfilesdir(officever:"14.0");

      path = hotfix_append_path(
        path  : common_path,
        value : "Microsoft Shared\Office14"
      );
      if (hotfix_check_fversion(file:"mso.dll", version:"14.0.7182.5000", path:path, kb:"3203460", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;
      if (hotfix_check_fversion(file:"ogl.dll", version:"14.0.7182.5000", path:path, kb:"3191848", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;

      path = hotfix_append_path(
        path  : common_path,
        value : "\Microsoft Shared\GRPHFLT"
      );
      if (hotfix_check_fversion(file:"epsimp32.flt", version:"2010.1400.7182.5000", min_version:"2010.1400.0.0", path:path, kb:"3203461", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;

      path = hotfix_get_officeprogramfilesdir(officever:"14.0");
      if (hotfix_check_fversion(file:"wwlibcxm.dll", version:"14.0.7182.5000", path:path, kb:"3203463", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;
      if (hotfix_check_fversion(file:"usp10.dll", version:"1.0626.7601.23800", path:path, kb:"3191844", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;
      if (hotfix_check_fversion(file:"offowc.dll", version:"14.0.7182.5000", path:path, kb:"3118389", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;
    }

    # The DCF folder is not always in the same bitness as Office, so
    # check both places
    path = hotfix_get_programfilesdir();
    path = hotfix_append_path(
      path  : path,
      value : "\Microsoft Office\Office15\DCF"
    );
    if (hotfix_check_fversion(file:"office.dll", version:"15.0.4937.1000", path:path, kb:"3162051", bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_programfilesdirx86();
    path = hotfix_append_path(
      path  : path,
      value : "\Microsoft Office\Office15\DCF"
    );
    if (hotfix_check_fversion(file:"office.dll", version:"15.0.4937.1000", path:path, kb:"3162051", bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;
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
        value : "Microsoft Shared\Office15"
      );
      if (hotfix_check_fversion(file:"mso.dll", version:"15.0.4937.1000", path:path, kb:"3203386", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;

      path = hotfix_append_path(
        path  : common_path,
        value : "Microsoft Shared\GRPHFLT"
      );
      if (hotfix_check_fversion(file:"epsimp32.flt", version:"2012.1500.4931.1000", min_version:"2012.1500.0.0", path:path, kb:"3203392", bulletin:bulletin, product:prod) == HCF_OLDER)
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

      kb   = "3191944";
      file = "mso.dll";
      path = hotfix_append_path(
        path  : common_path,
        value : "Microsoft Shared\Office16"
      );
      if (
        hotfix_check_fversion(file:file, version:"16.0.4549.1001", channel:"MSI", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.7329.1059", channel:"Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.7726.1042", channel:"Deferred", channel_version:"1701", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.8201.2102", channel:"First Release for Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.8201.2102", channel:"Current", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER
      )
        vuln = TRUE;

      kb   = "3178667";
      file = "mso20win32client.dll";
      # path is still <common files>\microsoft shared\office16
      if (
        hotfix_check_fversion(file:file, version:"16.0.4549.1000", channel:"MSI", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.7329.1059", channel:"Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.7726.1042", channel:"Deferred", channel_version:"1701", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.8201.2102", channel:"First Release for Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.8201.2102", channel:"Current", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER
      )
        vuln = TRUE;

      kb   = "3191882";
      file = "mso30win32client.dll";
      # path is still <common files>\microsoft shared\office16
      if (
        hotfix_check_fversion(file:file, version:"16.0.4549.1000", channel:"MSI", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.7329.1059", channel:"Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.7726.1042", channel:"Deferred", channel_version:"1701", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER #||
        #hotfix_check_fversion(file:file, version:"16.0.8201.2102", channel:"First Release for Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        #hotfix_check_fversion(file:file, version:"16.0.8201.2102", channel:"Current", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER
      )
        vuln = TRUE;

      kb   = "3191943";
      file = "mso299lwin32client.dll";
      # path is still <common files>\microsoft shared\office16
      if (
        hotfix_check_fversion(file:file, version:"16.0.4549.1000", channel:"MSI", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.7329.1059", channel:"Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.7726.1042", channel:"Deferred", channel_version:"1701", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.8201.2102", channel:"First Release for Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.8201.2102", channel:"Current", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER
      )
        vuln = TRUE;

      kb   = "3203383";
      file = "epsimp32.flt";
      path = hotfix_append_path(
        path  : common_path,
        value : "Microsoft Shared\GRPHFLT"
      );
      if (
        hotfix_check_fversion(file:file, version:"2012.1600.4540.1000", min_version:"2012.1600.0.0", channel:"MSI", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"2012.1600.7329.1059", min_version:"2012.1600.0.0", channel:"Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"2012.1600.7726.1042", min_version:"2012.1600.0.0", channel:"Deferred", channel_version:"1701", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"2012.1600.8201.1003", min_version:"2012.1600.0.0", channel:"First Release for Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"2012.1600.8201.1003", min_version:"2012.1600.0.0", channel:"Current", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER
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

  kb16 = "3191945";
  word_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6770.5000", "kb", "3203441"),
    "14.0", make_array("sp", 2, "version", "14.0.7182.5000", "kb", "3203464"),
    "15.0", make_array("sp", 1, "version", "15.0.4937.1000", "kb", "3203393"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4549.1000", "channel", "MSI", "kb", kb16),
      make_array("sp", 0, "version", "16.0.7369.2139", "channel", "Deferred", "kb", kb16),
      make_array("sp", 0, "version", "16.0.7766.2092", "channel", "Deferred", "channel_version", "1701", "kb", kb16),
      make_array("sp", 0, "version", "16.0.8201.2102", "channel", "First Release for Deferred", "kb", kb16),
      make_array("sp", 0, "version", "16.0.8201.2102", "channel", "Current", "kb", kb16)
    )
  );
  if (hotfix_check_office_product(product:"Word", checks:word_checks, bulletin:bulletin))
    vuln = TRUE;
}

######################################################################
# Compatibility Pack
######################################################################
function perform_comppack_checks()
{
  local_var install, installs, path;

  ####################################################################
  # Word Compatibility Pack
  ####################################################################
  installs = get_kb_list("SMB/Office/WordCnv/*/ProductPath");
  foreach install (keys(installs))
  {
    path = installs[install];
    path = ereg_replace(pattern:'^(.+)\\\\[^\\\\]+\\.exe$', replace:"\1\", string:path, icase:TRUE);
    if(hotfix_check_fversion(path:path, file:"wordcnv.dll",  version:"12.0.6770.5000", kb:"3203438", bulletin:bulletin, min_version:"12.0.0.0", product:"Microsoft Office Compatibility Pack") == HCF_OLDER)
      vuln = TRUE;
  }
}

######################################################################
# Word Viewer
######################################################################
function perform_viewer_checks()
{
  var install, installs, path;
  installs = get_kb_list("SMB/Office/WordViewer/*/ProductPath");
  foreach install (keys(installs))
  {
    path = installs[install];
    path = ereg_replace(pattern:'^(.+)\\\\[^\\\\]+\\.exe$', replace:"\1\", string:path, icase:TRUE);
    if(hotfix_check_fversion(path:path, file:"gdiplus.dll", version:"11.0.8442.0", kb:"3203484", bulletin:bulletin, product:"Microsoft Word Viewer") == HCF_OLDER)
      vuln = TRUE;
  }

  path = hotfix_get_officecommonfilesdir(officever:"11.0");
  path = hotfix_append_path(path:path, value:"Microsoft Shared\Office11");
  if(hotfix_check_fversion(path:path, file:"usp10.dll", version:"1.626.6002.24099", kb:"3203427", bulletin:bulletin, product:"Microsoft Word Viewer") == HCF_OLDER)
    vuln = TRUE;
}

######################################################################
# OneNote 2010
######################################################################
function perform_onenote_checks()
{
  var install, installs, prod, path;

  installs = get_installs(app_name:'Microsoft OneNote');
  foreach install (installs[1])
  {
    if (install["product"] == "2010" && install["sp"] == 2)
    {
      prod = "Microsoft OneNote 2010 SP2";
      path = tolower(install["path"]);
      path -= "onenote.exe";
      if (hotfix_check_fversion(file:"onenotesyncpc.dll", version:"14.0.7182.5000", path:path, kb:"3191908", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;
    }
  }
}

######################################################################
# Outlook 2007, 2010, 2013, 2016
######################################################################
function perform_outlook_checks()
{
  local_var checks, kb16;

  kb16 = "3191932";
  checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6770.5000", "kb", "3191898"),
    "14.0", make_array("sp", 2, "version", "14.0.7182.5000", "kb", "3203467"),
    "15.0", make_array("sp", 1, "version", "15.0.4937.1000", "kb", "3191938"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4549.1002", "channel", "MSI", "kb", kb16),
      make_array("sp", 0, "version", "16.0.7369.2139", "channel", "Deferred", "kb", kb16),
      make_array("sp", 0, "version", "16.0.7766.2092", "channel", "Deferred", "channel_version", "1701", "kb", kb16),
      make_array("sp", 0, "version", "16.0.8201.2102", "channel", "First Release for Deferred", "kb", kb16),
      make_array("sp", 0, "version", "16.0.8201.2102", "channel", "Current", "kb", kb16)
    )
  );
  if (hotfix_check_office_product(product:"Outlook", checks:checks, bulletin:bulletin))
    vuln = TRUE;
}

######################################################################
# PowerPoint 2007
######################################################################
function perform_powerpoint_checks()
{
  var install, installs, path;
  installs = get_kb_list("SMB/Office/PowerPoint/*/ProductPath");
  foreach install (keys(installs))
  {
    path = installs[install];
    path = ereg_replace(pattern:'^(.+)\\\\[^\\\\]+\\.exe$', replace:"\1\", string:path, icase:TRUE);
    if(hotfix_check_fversion(path:path, file:"ppcore.dll",  version:"12.0.6770.5000", kb:"3127888", bulletin:bulletin, min_version:"12.0.0.0", product:"Microsoft PowerPoint") == HCF_OLDER)
      vuln = TRUE;
  }
}

######################################################################
# MAIN
######################################################################
perform_office_checks();
perform_word_checks();
perform_comppack_checks();
perform_viewer_checks();
perform_onenote_checks();
perform_outlook_checks();
perform_powerpoint_checks();

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
