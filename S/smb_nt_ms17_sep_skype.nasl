#
# (C) Tenable Network Security, Inc.
#
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
  script_id(103123);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-8676", "CVE-2017-8695", "CVE-2017-8696");
  script_bugtraq_id(100755, 100773, 100780);
  script_xref(name:"MSKB", value:"4025865");
  script_xref(name:"MSKB", value:"4025866");
  script_xref(name:"MSKB", value:"4025867");
  script_xref(name:"MSKB", value:"4011040");
  script_xref(name:"MSKB", value:"3213568");
  script_xref(name:"MSKB", value:"4025868");
  script_xref(name:"MSKB", value:"4025869");
  script_xref(name:"MSFT", value:"MS17-4011107");
  script_xref(name:"MSFT", value:"MS17-4025865");
  script_xref(name:"MSFT", value:"MS17-4025866");
  script_xref(name:"MSFT", value:"MS17-4025867");
  script_xref(name:"MSFT", value:"MS17-4011040");
  script_xref(name:"MSFT", value:"MS17-3213568");
  script_xref(name:"MSFT", value:"MS17-4025868");
  script_xref(name:"MSFT", value:"MS17-4025869");
  script_xref(name:"IAVA", value:"2017-A-0274");

  script_name(english:"Security Updates for Microsoft Skype for Business and Microsoft Lync and Microsoft Live Meeting (September 2017)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Skype for Business or Microsoft Lync or Microsoft Live Meeting installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Skype for Business or Microsoft Lync or
Microsoft Live Meeting installation on the remote host is
missing security updates. It is, therefore, affected by
multiple vulnerabilities :

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
    addresses. (CVE-2017-8676)

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
    Uniscribe handles objects in memory. (CVE-2017-8696)");
  # https://support.microsoft.com/en-us/help/4011107/description-of-the-security-update-for-skype-for-business-2015-lync-20
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e352a51");
  # https://support.microsoft.com/en-us/help/4025865/descriptionofthesecurityupdateforlync2010september12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8b9ff1ff");
  # https://support.microsoft.com/en-us/help/4025866/descriptionofthesecurityupdateforlync2010attendeeseptember12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56771a41");
  # https://support.microsoft.com/en-us/help/4025867/descriptionofthesecurityupdateforlync2010attendeeseptember12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f1f4d2c3");
  # https://support.microsoft.com/en-us/help/4011040/descriptionofthesecurityupdateforskypeforbusiness2016september12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?64c04506");
  # https://support.microsoft.com/en-us/help/3213568/description-of-the-security-update-for-skype-for-business-2015-lync-20
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e876cd3b");
  # https://support.microsoft.com/en-us/help/4025868/descriptionofthesecurityupdateforofficelivemeetingconsoleseptember12-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f49fe21");
  # https://support.microsoft.com/en-us/help/4025869/descriptionofthesecurityupdateforofficelivemeetingadd-inseptember12-20
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8e609f52");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4011107
  -KB4025865
  -KB4025866
  -KB4025867
  -KB4011040
  -KB3213568
  -KB4025868
  -KB4025869");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8696");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:live_meeting_console");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:skype_for_business");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:live_meeting");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "microsoft_lync_server_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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
  '4025868', # Live Meeting 2007 Console
  '4011040', # Skype for Business 2016
  '4011107', # Lync 2013 SP1
  '3213568', # Lync 2013 SP1
  '4025866', # Lync 2010 Attendee (Admin level install)
  '4025865', # Lync 2010
  '4025867', # Lync 2010 Attendee (User level install)
  '4025869' # Live Meeting 2007 Add-in
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, "Failed to determine the location of %windir%.");

vuln = FALSE;
port = kb_smb_transport();

######################################################################
# Skype for Business 2016 / Lync 2013 and 2010
######################################################################
function perform_skype_checks()
{
  if (int(get_install_count(app_name:"Microsoft Lync")) <= 0)
    return NULL;

  var lync_install, lync_installs, kb, file, prod;
  var found, report, uninstall_key, uninstall_keys;

  lync_installs = get_installs(app_name:"Microsoft Lync");
  foreach lync_install (lync_installs[1])
  {

    if ("Live Meeting 2007 Add-in" >< lync_install["Product"])
    {
     if (hotfix_check_fversion(file:"lmaddins.dll", version:"8.0.6362.281", min_version:"8.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"4025869", product:"Live Meeting 2007 Add-in") == HCF_OLDER)
       vuln = TRUE;
    }
    if ("Live Meeting 2007 Console" >< lync_install["Product"])
    {
     if (hotfix_check_fversion(file:"bgpubmgr.exe", version:"8.0.6362.281", min_version:"8.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"4025868", product:"Live Meeting 2007 Console") == HCF_OLDER)
       vuln = TRUE;
    }
    # Lync 2010 checks
    if (lync_install["version"] =~ "^4\.0\." && "Server" >!< lync_install["Product"])
    {
      # Lync 2010
      if ("Attendee" >!< lync_install["Product"])
      {
        if (hotfix_check_fversion(file:"Ocpptview.dll", version:"4.0.7577.4540", min_version:"4.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"4025865", product:"Microsoft Lync 2010") == HCF_OLDER)
          vuln = TRUE;
      }
      # Lync 2010 Attendee
      else if ("Attendee" >< lync_install["Product"])
      {
        if ("user level" >< tolower(lync_install["Product"])) # User
        {
          if (hotfix_check_fversion(file:"Ocpptview.dll", version:"4.0.7577.4540", min_version:"4.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"4025867", product:lync_install["Product"]) == HCF_OLDER)
            vuln = TRUE;
        }
        else # Admin
        {
          if (hotfix_check_fversion(file:"Ocpptview.dll", version:"4.0.7577.4540", min_version:"4.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"4025866", product:lync_install["Product"]) == HCF_OLDER)
            vuln = TRUE;
        }
      }
    }
    # Lync on Skype 2016
    else if (lync_install["version"] =~ "^16\.0\." && "Server" >!< lync_install["Product"])
    {
      file = "Lync.exe";
      prod = "Skype for Business 2016";
      kb = "4011040";

      # MSI
      if (lync_install['Channel'] == "MSI" || empty_or_null(lync_install['Channel']))
      {
        if (hotfix_check_fversion(file:file, version:"16.0.4588.1000", channel:"MSI", channel_product:"Lync", path:lync_install["path"], kb:kb, product:prod) == HCF_OLDER)
          vuln = TRUE;
      }
      # Deferred
      else if (lync_install['Channel'] == "Deferred")
      {
        if (
          hotfix_check_fversion(file:file, version:"16.0.8201.2193", channel:"Deferred", channel_product:"Lync", path:lync_install["path"], kb:kb, product:prod) == HCF_OLDER ||
          hotfix_check_fversion(file:file, version:"16.0.7766.2116", channel:"Deferred", channel_version:"1701", channel_product:"Lync", path:lync_install["path"], kb:kb, product:prod) == HCF_OLDER
        )
          vuln = TRUE;
      }
      else if (lync_install['Channel'] == "First Release for Deferred")
      {
        if (hotfix_check_fversion(file:file, version:"16.0.8431.2079", channel:"First Release for Deferred", channel_product:"Lync", path:lync_install["path"], kb:kb, product:prod) == HCF_OLDER)
          vuln = TRUE;
      }
      else if (lync_install['Channel'] == "Current")
      {
        if (hotfix_check_fversion(file:file, version:"16.0.8326.2107", channel:"Current", channel_product:"Lync", path:lync_install["path"], kb:kb, product:prod) == HCF_OLDER)
          vuln = TRUE;
      }
    } # Lync 2013 
    else if (lync_install["version"] =~ "^15\.0\." && "Server" >!< lync_install["Product"])
     {
       if (hotfix_check_fversion(file:"lync.exe", version:"15.0.4963.1000", min_version:"15.0.4000.1000", path:lync_install["path"], bulletin:bulletin, kb:"4011107", product:"Microsoft Lync 2013") == HCF_OLDER)
         vuln = TRUE;

     }
  }
}

perform_skype_checks();

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
