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
  script_id(149479);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/27");

  script_cve_id("CVE-2021-26421", "CVE-2021-26422");
  script_xref(name:"MSKB", value:"5003729");
  script_xref(name:"MSFT", value:"MS21-5003729");
  script_xref(name:"IAVA", value:"2021-A-0217-S");

  script_name(english:"Security Updates for Microsoft Skype for Business (May 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Skype for Business installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Skype for Business installation on the remote
host is missing security updates. It is, therefore, affected
by multiple vulnerabilities:

  - A session spoofing vulnerability exists. An attacker can
    exploit this to perform actions with the privileges of
    another user. (CVE-2021-26421)

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2021-26422)");
  # https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-skype-for-business-server-and-lync-server-may-11-2021-kb5003729-3a6def2e-4b74-480e-bf24-fbec151f10a0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d97ea49");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB5003729 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26422");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:skype_for_business");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "microsoft_lync_server_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}


include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('install_func.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

var bulletin = 'MS21-05';
var kbs = make_list(
  '5003729'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('installed_sw/Microsoft Lync');

get_kb_item_or_exit('SMB/Registry/Uninstall/Enumerated', exit_code:1);

var uninstall_list = get_kb_list('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');

if (isnull(uninstall_list)) exit(1, 'Missing uninstall enumeration list.');

var vuln = FALSE;

var name_kb, prod, version_kb, kb, version, info;

foreach name_kb (keys(uninstall_list))
{
  prod = uninstall_list[name_kb];
  version_kb = name_kb - '/DisplayName' + '/DisplayVersion';

  if (
    'Server' >< prod &&
    (
      'Core Components' >< prod ||
      'Macp Web Components' >< prod
    )
  )
  {
    if ('Skype for Business' >< prod)
    {
      if ('2019' >< prod)
      {
        version = get_kb_item(version_kb);
        if (!isnull(version) && (ver_compare(ver:version, minver:'7.0.2046.0', fix:'7.0.2046.369') < 0))
        {
          vuln = TRUE;
          kb = '5003729'; # This is one of the KBs. MS needs to clean up some linking stuff.
          info = '\n  Product           : ' + prod +
                 '\n  Installed Version : ' + version +
                 '\n  Fixed Version     : 7.0.2046.369\n';
          hotfix_add_report(info, bulletin:bulletin, kb:kb);
        }
      }
      else if ('2015' >< prod && 'Macp' >!< prod)
      {
        version = get_kb_item(version_kb);
        if (!isnull(version) && (ver_compare(ver:version, minver:'6.0.9319.0', fix:'6.0.9319.606') < 0))
        {
          vuln = TRUE;
          kb = '5003729'; # This is one of the KBs. MS needs to clean up some linking stuff.
          # The other relevant KB is KB5000688 but only applies to 2015 and 2013
          info = '\n  Product           : ' + prod +
                 '\n  Installed Version : ' + version +
                 '\n  Fixed Version     : 6.0.9319.606\n';
          hotfix_add_report(info, bulletin:bulletin, kb:kb);
        }
      }
    }
    else if ('Lync' >< prod && '2013' >< prod && 'Macp' >!< prod)
    {
      version = get_kb_item(version_kb);
      if (!isnull(version) && (ver_compare(ver:version, minver:'5.0.8308.0', fix:'5.0.8308.1144') < 0))
      {
        vuln = TRUE;
        kb = '5003729'; # This is one of the KBs. MS needs to clean up some linking stuff.
        # The other relevant KB is KB5000688 but only applies to 2015 and 2013
        info = '\n  Product           : ' + prod +
               '\n  Installed Version : ' + version +
               '\n  Fixed Version     : 5.0.8308.1144\n';
        hotfix_add_report(info, bulletin:bulletin, kb:kb);
      }
    }
  }
}

if (vuln)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  exit(0);
}
else
{
  audit(AUDIT_HOST_NOT, 'affected');
}
