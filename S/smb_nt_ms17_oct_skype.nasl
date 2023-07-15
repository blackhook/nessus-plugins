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
  script_id(103753);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/17");

  script_cve_id("CVE-2017-11786");
  script_bugtraq_id(101156);
  script_xref(name:"MSKB", value:"4011179");
  script_xref(name:"MSFT", value:"MS17-4011159");
  script_xref(name:"MSFT", value:"MS17-4011179");
  script_xref(name:"IAVA", value:"2017-A-0291-S");

  script_name(english:"Security Updates for Microsoft Skype for Business and Microsoft Lync (October 2017)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Skype for Business or Microsoft Lync installation on 
the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Skype for Business or Microsoft Lync
installation on the remote host is missing a security
update. It is, therefore, affected by the following
vulnerability :

  - An elevation of privilege vulnerability exists when
    Skype for Business fails to properly handle specific
    authentication requests. An authenticated attacker who
    successfully exploited this vulnerability could steal an
    authentication hash that can be reused elsewhere. The
    attacker could then take any action that the user had
    permissions for, causing possible outcomes that could
    vary between users.  (CVE-2017-11786)");
  # https://support.microsoft.com/en-us/help/4011159/description-of-the-security-update-for-skype-for-business-2016-october
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f9f0309");
  # https://support.microsoft.com/en-us/help/4011179/descriptionofthesecurityupdateforskypeforbusiness2015-lync2013-october
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b6d55525");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4011159
  -KB4011179");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11786");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:skype_for_business");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  '4011159', # Skype for Business 2016
  '4011179'  # lync 2013
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
    # Lync on Skype 2016
    if (lync_install["version"] =~ "^16\.0\." && "Server" >!< lync_install["Product"])
    {
      file = "Lync.exe";
      prod = "Skype for Business 2016";
      kb = "4011159";

      # MSI
      if (lync_install['Channel'] == "MSI" || empty_or_null(lync_install['Channel']))
      {
        if (hotfix_check_fversion(file:file, version:"16.0.4600.1000", channel:"MSI", channel_product:"Lync", path:lync_install["path"], kb:kb, product:prod) == HCF_OLDER)
          vuln = TRUE;
      }
      # Deferred
      else if (lync_install['Channel'] == "Deferred")
      {
        if (
          hotfix_check_fversion(file:file, version:"16.0.8201.2200", channel:"Deferred", channel_version:"1705", channel_product:"Lync", path:lync_install["path"], kb:kb, product:prod) == HCF_OLDER ||
          hotfix_check_fversion(file:file, version:"16.0.7766.2119", channel:"Deferred", channel_product:"Lync", path:lync_install["path"], kb:kb, product:prod) == HCF_OLDER  
        )
          vuln = TRUE;
      }
      else if (lync_install['Channel'] == "First Release for Deferred")
      {
        if (hotfix_check_fversion(file:file, version:"16.0.8431.2107", channel:"First Release for Deferred", channel_product:"Lync", path:lync_install["path"], kb:kb, product:prod) == HCF_OLDER)
          vuln = TRUE;
      }
      else if (lync_install['Channel'] == "Current")
      {
        if (hotfix_check_fversion(file:file, version:"16.0.8431.2107", channel:"Current", channel_product:"Lync", path:lync_install["path"], kb:kb, product:prod) == HCF_OLDER)
          vuln = TRUE;
      }
    } 
    # Lync 2013 
    else if (lync_install["version"] =~ "^15\.0\." && "Server" >!< lync_install["Product"])
     {
       if (hotfix_check_fversion(file:"lync.exe", version:"15.0.4971.1000", min_version:"15.0.4000.1000", path:lync_install["path"], bulletin:bulletin, kb:"4011179", product:"Microsoft Lync 2013") == HCF_OLDER)
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
