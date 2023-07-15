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
  script_id(111045);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-8238", "CVE-2018-8311");
  script_bugtraq_id(104619, 104624);
  script_xref(name:"MSKB", value:"4022221");
  script_xref(name:"MSKB", value:"4022225");
  script_xref(name:"MSFT", value:"MS18-4022221");
  script_xref(name:"MSFT", value:"MS18-4022225");

  script_name(english:"Security Updates for Microsoft Skype for Business and Microsoft Lync (July 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Skype for Business or Microsoft Lync installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Skype for Business or Microsoft Lync
installation on the remote host is missing security updates.
It is, therefore, affected by multiple vulnerabilities :

  - A security feature bypass vulnerability exists when
    Skype for Business or Lync do not properly parse UNC
    path links shared via messages. An attacker who
    successfully exploited the vulnerability could execute
    arbitrary commands in the context of the logged-in user.
    The security feature bypass by itself does not allow
    arbitrary code execution. Instead, an attacker would
    have to convince users to click a link to a file. In a
    file-sharing attack scenario, an attacker could provide
    a specially-crafted file designed to exploit the
    vulnerability, and then convince a user to click the
    link to the file. The update addresses the vulnerability
    by correcting how Skype for Business and Lync handle
    links to UNC paths. (CVE-2018-8238)

  - A remote code execution vulnerability exists when Skype
    for Business and Microsoft Lync clients fail to properly
    sanitize specially crafted content. The vulnerability
    could corrupt memory in a way that could allow an
    attacker to execute arbitrary code in the context of the
    current user. An attacker who successfully exploited the
    vulnerability could gain the same user rights as the
    current user.  (CVE-2018-8311)");
  # https://support.microsoft.com/en-us/help/4022221/description-of-the-security-update-for-skype-for-business-2016-july-10
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?545ab530");
  # https://support.microsoft.com/en-us/help/4022225/description-of-the-security-update-for-skype-for-business-2015-lync
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c06c463");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4022221
  -KB4022225");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8238");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:skype_for_business");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS18-07";
kbs = make_list(
  '4022221', # Skype for Business 2016
  '4022225'  # lync 2013
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
      kb = "4022221";

      # MSI
      if (lync_install['Channel'] == "MSI" || empty_or_null(lync_install['Channel']))
      {
        if (hotfix_check_fversion(file:file, version:"16.0.4717.1000", channel:"MSI", channel_product:"Lync", path:lync_install["path"], kb:kb, product:prod) == HCF_OLDER)
          vuln = TRUE;
      }
      # Deferred
      else if (lync_install['Channel'] == "Deferred")
      {
        if (
          hotfix_check_fversion(file:file, version:"16.0.9126.2259", channel:"Deferred", channel_version:"1803", channel_product:"Lync", path:lync_install["path"], kb:kb, product:prod) == HCF_OLDER ||
          hotfix_check_fversion(file:file, version:"16.0.8431.2280", channel:"Deferred", channel_product:"Lync", path:lync_install["path"], kb:kb, product:prod) == HCF_OLDER
        )
          vuln = TRUE;
      }
      else if (lync_install['Channel'] == "First Release for Deferred")
      {
        if (hotfix_check_fversion(file:file, version:"16.0.9126.2259", channel:"First Release for Deferred", channel_product:"Lync", path:lync_install["path"], kb:kb, product:prod) == HCF_OLDER)
          vuln = TRUE;
      }
      else if (lync_install['Channel'] == "Current")
      {
        if (hotfix_check_fversion(file:file, version:"16.0.10228.20104", channel:"Current", channel_product:"Lync", path:lync_install["path"], kb:kb, product:prod) == HCF_OLDER)
          vuln = TRUE;
      }
    }
    # Lync 2013 
    else if (lync_install["version"] =~ "^15\.0\." && "Server" >!< lync_install["Product"])
    {
      if (hotfix_check_fversion(file:"lync.exe", version:"15.0.5049.1000", min_version:"15.0.4000.1000", path:lync_install["path"], bulletin:bulletin, kb:"4022225", product:"Microsoft Lync 2013") == HCF_OLDER)
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
