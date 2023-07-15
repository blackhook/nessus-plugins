#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(100768);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/17");

  script_cve_id("CVE-2017-0283");
  script_bugtraq_id(98920);
  script_xref(name:"MSKB", value:"3203382");
  script_xref(name:"MSKB", value:"3191939");
  script_xref(name:"MSKB", value:"4020732");
  script_xref(name:"MSKB", value:"4020733");
  script_xref(name:"MSKB", value:"4020734");
  script_xref(name:"MSKB", value:"4020735");
  script_xref(name:"MSKB", value:"4020736");
  script_xref(name:"MSFT", value:"MS17-3203382");
  script_xref(name:"MSFT", value:"MS17-3191939");
  script_xref(name:"MSFT", value:"MS17-4020732");
  script_xref(name:"MSFT", value:"MS17-4020733");
  script_xref(name:"MSFT", value:"MS17-4020734");
  script_xref(name:"MSFT", value:"MS17-4020735");
  script_xref(name:"MSFT", value:"MS17-4020736");
  script_xref(name:"IAVA", value:"2017-A-0179-S");

  script_name(english:"Security Update for Live Meeting 2007 / Lync 2010 and 2013 / Skype for Business 2016 (June 2017)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Live Meeting 2007, Lync 2010, Lync 2013, or Skype 2016
for Business application installed on the remote Windows host is
missing a security update. It is, therefore, affected remote code
execution vulnerability in Windows Uniscribe software due to improper
handling of objects in memory. An unauthenticated, remote attacker
can exploit this, by convincing a user to visit a specially crafted
website or to open a specially crafted document file, to execute
arbitrary code in the context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/3203382/descriptionofthesecurityupdateforskypeforbusiness2016june13-2017");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/3191939/description-of-the-security-update-for-skype-for-business-2015-lync-20");
  # https://support.microsoft.com/en-us/help/4020732/security-update-for-microsoft-lync-2010
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?19ae218b");
  # https://support.microsoft.com/en-us/help/4020733/description-of-the-security-update-for-microsoft-lync-2010-attendee
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?230084fb");
  # https://support.microsoft.com/en-us/help/4020734/security-update-for-microsoft-lync-2010-attendee-user-level-install
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9297a074");
  # https://support.microsoft.com/en-us/help/4020735/security-update-for-microsoft-live-meeting-2007-console
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?37af777f");
  # https://support.microsoft.com/en-us/help/4020736/security-update-for-microsoft-live-meeting-2007-add-in
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c3c3e16");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Lync 2010, Lync 2013, and
Skype for Business 2016.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:live_meeting_console");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:skype_for_business");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:live_meeting");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2023 Tenable Network Security, Inc.");

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

bulletin = "MS17-06";
kbs = make_list(
  '3191939', # Lync 2013 SP1
  '3203382', # Skype for Business 2016
  '4020732', # Lync 2010
  '4020733', # Lync 2010 Attendee (Admin level install)
  '4020734', # Lync 2010 Attendee (User level install)
  '4020735', # Live Meeting 2007 Console
  '4020736'  # Live Meeting 2007 Add-in
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
  var found, report, uninstall_key, uninstall_keys, skip;

  lync_installs = get_installs(app_name:"Microsoft Lync");
  foreach lync_install (lync_installs[1])
  {
    if ("Live Meeting 2007 Console" >< lync_install["Product"])
    {
     if (hotfix_check_fversion(file:"bgpubmgr.exe", version:"8.0.6362.274", min_version:"8.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"4020735", product:"Live Meeting 2007 Console") == HCF_OLDER)
       vuln = TRUE;
    }
    if ("Live Meeting 2007 Add-in" >< lync_install["Product"])
    {
     if (hotfix_check_fversion(file:"lmaddins.dll", version:"8.0.6362.274", min_version:"8.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"4020736", product:"Live Meeting 2007 Add-in") == HCF_OLDER)
       vuln = TRUE;
    }
    # Lync 2010 checks
    if (lync_install["version"] =~ "^4\.0\." && "Server" >!< lync_install["Product"])
    {
      # Lync 2010
      if ("Attendee" >!< lync_install["Product"])
      {
        if (hotfix_check_fversion(file:"Ocpptview.dll", version:"4.0.7577.4534", min_version:"4.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"4020732", product:"Microsoft Lync 2010") == HCF_OLDER)
          vuln = TRUE;
      }
      # Lync 2010 Attendee
      else if ("Attendee" >< lync_install["Product"])
      {
        if ("user level" >< tolower(lync_install["Product"])) # User
        {
          if (hotfix_check_fversion(file:"Ocpptview.dll", version:"4.0.7577.4534", min_version:"4.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"4020734", product:lync_install["Product"]) == HCF_OLDER)
            vuln = TRUE;
        }
        else # Admin
        {
          if (hotfix_check_fversion(file:"Ocpptview.dll", version:"4.0.7577.4534", min_version:"4.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"4020733", product:lync_install["Product"]) == HCF_OLDER)
            vuln = TRUE;
        }
      }
    }
    # Lync 2013 / Skype 2016
    else if (lync_install["version"] =~ "^16\.0\." && "Server" >!< lync_install["Product"])
    {
      file = "Lync.exe";
      prod = "Skype for Business 2016";
      kb = "3203382";

      # MSI
      if (lync_install['Channel'] == "MSI" || empty_or_null(lync_install['Channel']))
      {
        if (hotfix_check_fversion(file:file, version:"16.0.4546.1000", channel:"MSI", channel_product:"Lync", path:lync_install["path"], kb:kb, product:prod) == HCF_OLDER)
          vuln = TRUE;
      }
      # Deferred
      else if (lync_install['Channel'] == "Deferred")
      {
        if (
          hotfix_check_fversion(file:file, version:"16.0.7369.2139", channel:"Deferred", channel_product:"Lync", path:lync_install["path"], kb:kb, product:prod) == HCF_OLDER ||
          hotfix_check_fversion(file:file, version:"16.0.7766.2092", channel:"Deferred", channel_version:"1701", channel_product:"Lync", path:lync_install["path"], kb:kb, product:prod) == HCF_OLDER
        )
          vuln = TRUE;
      }
      else if (lync_install['Channel'] == "First Release for Deferred")
      {
        if (hotfix_check_fversion(file:file, version:"16.0.8201.2102", channel:"First Release for Deferred", channel_product:"Lync", path:lync_install["path"], kb:kb, product:prod) == HCF_OLDER)
          vuln = TRUE;
      }
      else if (lync_install['Channel'] == "Current")
      {
        if (hotfix_check_fversion(file:file, version:"16.0.8201.2102", channel:"Current", channel_product:"Lync", path:lync_install["path"], kb:kb, product:prod) == HCF_OLDER)
          vuln = TRUE;
      }
    }
    else if (lync_install["version"] =~ "^15\.0\." && "Server" >!< lync_install["Product"])
    {
      if (hotfix_check_fversion(file:"Lync.exe", version:"15.0.4933.1000", min_version:"15.0.4700.1000", path:lync_install["path"], bulletin:bulletin, kb:"3191939", product:"Microsoft Lync 2013 (Skype for Business)") == HCF_OLDER)
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
