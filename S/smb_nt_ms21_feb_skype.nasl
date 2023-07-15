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
  script_id(146340);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/13");

  script_cve_id("CVE-2021-24073", "CVE-2021-24099");
  script_xref(name:"MSKB", value:"5000675");
  script_xref(name:"MSKB", value:"5000688");
  script_xref(name:"MSFT", value:"MS21-5000675");
  script_xref(name:"MSFT", value:"MS21-5000688");
  script_xref(name:"IAVA", value:"2021-A-0088-S");

  script_name(english:"Security Updates for Microsoft Skype for Business (February 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Skype for Business installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Skype for Business installation on the remote
host is missing security updates. It is, therefore, affected
by multiple vulnerabilities:

  - A session spoofing vulnerability exists. An attacker can
    exploit this to perform actions with the privileges of
    another user. (CVE-2021-24073)

  - A denial of service (DoS) vulnerability. An attacker can
    exploit this issue to cause the affected component to
    deny system or application services. (CVE-2021-24099)");
  # https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-skype-for-business-server-and-lync-server-february-9-2021-kb5000675-fa2b0688-72f6-4bde-b145-c48b5c503cec
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a701d748");
  # https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-skype-for-business-server-and-lync-server-february-9-2021-kb5000688-6e8431f9-6080-445c-80c2-34e6dde61bec
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ed486606");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB5000675
  -KB5000688");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-24073");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:skype_for_business");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = 'MS21-02';
kbs = make_list(
  '5000675',
  '5000688'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

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
        if (!isnull(version) && (ver_compare(ver:version, minver:'7.0.2046.0', fix:'7.0.2046.252') < 0))
        {
          vuln = TRUE;
          kb = '5000675'; # This is one of the KBs. MS needs to clean up some linking stuff.
          info = '\n  Product           : ' + prod +
                 '\n  Installed Version : ' + version +
                 '\n  Fixed Version     : 7.0.2046.252\n';
          hotfix_add_report(info, bulletin:bulletin, kb:kb);
        }
      }
      else if ('2015' >< prod && 'Macp' >!< prod)
      {
        version = get_kb_item(version_kb);
        if (!isnull(version) && (ver_compare(ver:version, minver:'6.0.9319.0', fix:'6.0.9319.601') < 0))
        {
          vuln = TRUE;
          kb = '5000675'; # This is one of the KBs. MS needs to clean up some linking stuff.
          # The other relevant KB is KB5000688 but only applies to 2015 and 2013
          info = '\n  Product           : ' + prod +
                 '\n  Installed Version : ' + version +
                 '\n  Fixed Version     : 6.0.9319.601\n';
          hotfix_add_report(info, bulletin:bulletin, kb:kb);
        }
      }
    }
    else if ('Lync' >< prod && '2013' >< prod && 'Macp' >!< prod)
    {
      version = get_kb_item(version_kb);
      if (!isnull(version) && (ver_compare(ver:version, minver:'5.0.8308.0', fix:'5.0.8308.1136') < 0))
      {
        vuln = TRUE;
        kb = '5000675'; # This is one of the KBs. MS needs to clean up some linking stuff.
        # The other relevant KB is KB5000688 but only applies to 2015 and 2013
        info = '\n  Product           : ' + prod +
               '\n  Installed Version : ' + version +
               '\n  Fixed Version     : 5.0.8308.1136\n';
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
