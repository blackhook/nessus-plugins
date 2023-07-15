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
  script_id(118929);
  script_version("1.6");
  script_cvs_date("Date: 2019/04/05 23:25:09");

  script_cve_id("CVE-2018-8546");
  script_bugtraq_id(105802);
  script_xref(name:"MSKB", value:"4461473");
  script_xref(name:"MSKB", value:"4461487");
  script_xref(name:"MSFT", value:"MS18-4461473");
  script_xref(name:"MSFT", value:"MS18-4461487");

  script_name(english:"Security Updates for Microsoft Skype for Business and Microsoft Lync (November 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
  "The Microsoft Skype for Business or Microsoft Lync installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Skype for Business or Microsoft Lync
installation on the remote host is missing a security
update. It is, therefore, affected by the following
vulnerability :

  - A denial of service vulnerability exists in Skype for
    Business. An attacker who successfully exploited the
    vulnerability could cause Skype for Business to stop
    responding. Note that the denial of service would not
    allow an attacker to execute code or to elevate the
    attacker's user rights. For an attack to be successful,
    this vulnerability requires that a user sends a number
    of emojis in the affected version of Skype for Business.
    The security update addresses the vulnerability by
    correcting how Skype for Business handles emojis.
    (CVE-2018-8546)");
  # https://support.microsoft.com/en-us/help/4461473/description-of-the-security-update-for-skype-for-business-2016
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f60e70b");
  # https://support.microsoft.com/en-us/help/4461487/description-of-the-security-update-for-skype-for-business-2015-lync
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7fddc29c");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4461473
  -KB4461487");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8546");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:skype_for_business");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl","microsoft_lync_server_installed.nasl","smb_hotfixes.nasl","ms_bulletin_checks_possible.nasl");
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
include("obj.inc");

global_var vuln;


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS18-11";
kbs = make_list(
  '4461473', # Skype for Business 2016
  '4461487'  # Skype for Business 2015 (Lync 2013)
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, "Failed to determine the location of %windir%.");

vuln = FALSE;
port = kb_smb_transport();

function perform_skype_checks()
{
  if (int(get_install_count(app_name:"Microsoft Lync")) <= 0)
    return NULL;

  var lync_install, lync_installs, kb, file, prod;
  var found, report, uninstall_key, uninstall_keys;

  lync_installs = get_installs(app_name:"Microsoft Lync");

  foreach lync_install (lync_installs[1])
  {
    # Lync on Skype 2016 (Basic)
    if (
      lync_install["version"] =~ "^16\.0\." &&
      "Server" >!< lync_install["Product"]
    )
    {
      file = "Lync.exe";
      prod = "Microsoft Lync";
      kb = "4461473";

      if (hotfix_check_fversion(file:file, version:"16.0.4771.1000", path:lync_install["path"], bulletin:bulletin, kb:kb, product:prod) == HCF_OLDER)
          vuln = TRUE;
    }
    else if (
      lync_install["version"] =~ "^15\.0\." &&
      "Server" >!< lync_install["Product"]
    )
    {
      if (hotfix_check_fversion(file:"Lync.exe", version:"15.0.5085.1000", min_version:"15.0.4000.1000", path:lync_install["path"], bulletin:bulletin, kb:"4461487", product:"Microsoft Lync 2013") == HCF_OLDER)
        vuln = TRUE;
    }
  }
}
perform_skype_checks();

if (vuln)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
hotfix_check_fversion_end();
audit(AUDIT_HOST_NOT, 'affected');
}
