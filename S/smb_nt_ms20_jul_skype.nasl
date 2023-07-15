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
  script_id(139314);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/05");

  script_cve_id("CVE-2020-1025");
  script_xref(name:"MSKB", value:"4571332");
  script_xref(name:"MSKB", value:"4571333");
  script_xref(name:"MSKB", value:"4571334");
  script_xref(name:"MSFT", value:"MS20-4571332");
  script_xref(name:"MSFT", value:"MS20-4571333");
  script_xref(name:"MSFT", value:"MS20-4571334");

  script_name(english:"Security Updates for Microsoft Skype for Business (July 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Skype for Business installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Skype for Business installation on the remote
host is missing a security update. It is, therefore,
affected by the following vulnerability :

  - An elevation of privilege vulnerability exists when
    Microsoft SharePoint Server and Skype for Business
    Server improperly handle OAuth token validation. An
    attacker who successfully exploited the vulnerability
    could bypass authentication and achieve improper access.
    (CVE-2020-1025)");
  # https://support.microsoft.com/en-us/help/4571332/description-of-the-security-update-for-skype-for-business-server-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6a64541d");
  # https://support.microsoft.com/en-us/help/4571333/description-of-the-security-update-for-skype-for-business-server-2015
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e36ad5f");
  # https://support.microsoft.com/en-us/help/4571334/description-of-the-security-update-for-lync-server-2013-july-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b2c18bf1");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4571332
  -KB4571333
  -KB4571334");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1025");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:skype_for_business");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "microsoft_lync_server_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('install_func.inc');

global_var vuln;


get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS20-07';
kbs = make_list(
  '4571332', # Skype for Business Server 2019 CU 2
  '4571333', # Skype for Business Server 2015 CU 8
  '4571334'  # Microsoft Lync Server 2013
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('installed_sw/Microsoft Lync');

get_kb_item_or_exit('SMB/Registry/Uninstall/Enumerated', exit_code:1);

uninstall_list = get_kb_list('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');

if (isnull(uninstall_list)) exit(1, 'Missing uninstall enumeration list.');

vuln = FALSE;

foreach name_kb (keys(uninstall_list))
{
  prod = uninstall_list[name_kb];
  version_kb = name_kb - '/DisplayName' + '/DisplayVersion';

  if (
    'Server' >< prod &&
    (
      'Core Components' >< prod ||
      'Web Components Server' >< prod ||
      'Macp Web Components' >< prod
    )
  )
  {
    if ('Skype for Business' >< prod)
    {
      if ('2019' >< prod)
      {
        version = get_kb_item(version_kb);
        if (!isnull(version) && (ver_compare(ver:version, minver:'7.0.2046.0', fix:'7.0.2046.236') < 0))
        {
          vuln = TRUE;
          kb = '4571332';
          info = '\n  Product           : ' + prod +
                 '\n  Installed Version : ' + version +
                 '\n  Fixed Version     : 7.0.2046.236\n';
          hotfix_add_report(info, bulletin:bulletin, kb:kb);
        }
      }
      else if ('2015' >< prod && 'Macp' >!< prod)
      {
        version = get_kb_item(version_kb);
        if (!isnull(version) && (ver_compare(ver:version, minver:'6.0.9319.0', fix:'6.0.9319.591') < 0))
        {
          vuln = TRUE;
          kb = '4571333';
          info = '\n  Product           : ' + prod +
                 '\n  Installed Version : ' + version +
                 '\n  Fixed Version     : 6.0.9319.591\n';
          hotfix_add_report(info, bulletin:bulletin, kb:kb);
        }
      }
    }
    else if ('Lync' >< prod && '2013' >< prod && 'Macp' >!< prod)
    {
      version = get_kb_item(version_kb);
      if (!isnull(version) && (ver_compare(ver:version, minver:'5.0.8308.0', fix:'5.0.8308.1134') < 0))
      {
        vuln = TRUE;
        kb = '4571334';
        info = '\n  Product           : ' + prod +
               '\n  Installed Version : ' + version +
               '\n  Fixed Version     : 5.0.8308.1134\n';
        hotfix_add_report(info, bulletin:bulletin, kb:kb);
      }
    }
  }
}

if (vuln)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  exit(0);
}
else
{
  audit(AUDIT_HOST_NOT, 'affected');
}
