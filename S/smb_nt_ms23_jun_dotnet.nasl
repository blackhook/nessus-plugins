#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(177393);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/19");

  script_cve_id(
    "CVE-2023-24895",
    "CVE-2023-24897",
    "CVE-2023-24936",
    "CVE-2023-29326",
    "CVE-2023-29330",
    "CVE-2023-29331",
    "CVE-2023-32030"
  );
  script_xref(name:"IAVA", value:"2023-A-0291");
  script_xref(name:"MSKB", value:"5027107");
  script_xref(name:"MSKB", value:"5027108");
  script_xref(name:"MSKB", value:"5027109");
  script_xref(name:"MSKB", value:"5027110");
  script_xref(name:"MSKB", value:"5027111");
  script_xref(name:"MSKB", value:"5027112");
  script_xref(name:"MSKB", value:"5027113");
  script_xref(name:"MSKB", value:"5027114");
  script_xref(name:"MSKB", value:"5027115");
  script_xref(name:"MSKB", value:"5027116");
  script_xref(name:"MSKB", value:"5027117");
  script_xref(name:"MSKB", value:"5027118");
  script_xref(name:"MSKB", value:"5027119");
  script_xref(name:"MSKB", value:"5027121");
  script_xref(name:"MSKB", value:"5027122");
  script_xref(name:"MSKB", value:"5027123");
  script_xref(name:"MSKB", value:"5027124");
  script_xref(name:"MSKB", value:"5027125");
  script_xref(name:"MSKB", value:"5027126");
  script_xref(name:"MSKB", value:"5027127");
  script_xref(name:"MSKB", value:"5027128");
  script_xref(name:"MSKB", value:"5027129");
  script_xref(name:"MSKB", value:"5027131");
  script_xref(name:"MSKB", value:"5027132");
  script_xref(name:"MSKB", value:"5027133");
  script_xref(name:"MSKB", value:"5027134");
  script_xref(name:"MSKB", value:"5027138");
  script_xref(name:"MSKB", value:"5027139");
  script_xref(name:"MSKB", value:"5027140");
  script_xref(name:"MSKB", value:"5027141");
  script_xref(name:"MSFT", value:"MS23-5027107");
  script_xref(name:"MSFT", value:"MS23-5027108");
  script_xref(name:"MSFT", value:"MS23-5027109");
  script_xref(name:"MSFT", value:"MS23-5027110");
  script_xref(name:"MSFT", value:"MS23-5027111");
  script_xref(name:"MSFT", value:"MS23-5027112");
  script_xref(name:"MSFT", value:"MS23-5027113");
  script_xref(name:"MSFT", value:"MS23-5027114");
  script_xref(name:"MSFT", value:"MS23-5027115");
  script_xref(name:"MSFT", value:"MS23-5027116");
  script_xref(name:"MSFT", value:"MS23-5027117");
  script_xref(name:"MSFT", value:"MS23-5027118");
  script_xref(name:"MSFT", value:"MS23-5027119");
  script_xref(name:"MSFT", value:"MS23-5027121");
  script_xref(name:"MSFT", value:"MS23-5027122");
  script_xref(name:"MSFT", value:"MS23-5027123");
  script_xref(name:"MSFT", value:"MS23-5027124");
  script_xref(name:"MSFT", value:"MS23-5027125");
  script_xref(name:"MSFT", value:"MS23-5027126");
  script_xref(name:"MSFT", value:"MS23-5027127");
  script_xref(name:"MSFT", value:"MS23-5027128");
  script_xref(name:"MSFT", value:"MS23-5027129");
  script_xref(name:"MSFT", value:"MS23-5027131");
  script_xref(name:"MSFT", value:"MS23-5027132");
  script_xref(name:"MSFT", value:"MS23-5027133");
  script_xref(name:"MSFT", value:"MS23-5027134");
  script_xref(name:"MSFT", value:"MS23-5027138");
  script_xref(name:"MSFT", value:"MS23-5027139");
  script_xref(name:"MSFT", value:"MS23-5027140");
  script_xref(name:"MSFT", value:"MS23-5027141");

  script_name(english:"Security Updates for Microsoft .NET Framework (June 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update. It is, therefore, affected
by multiple vulnerabilities, as follows:

  - A remote code execution vulnerability in the MSDIA SDK where corrupted PDBs can cause a heap overflow.
   (CVE-2023-24897)

  - A remote code execution vulnerability in WPF where the BAML offers other ways to instantiate types.
    (CVE-2023-21808)

  - A remote code execution vulnerability in the WPF XAML parser (CVE-2023-24895)");
  # https://devblogs.microsoft.com/dotnet/dotnet-framework-june-2023-security-and-quality-rollup/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?283f4db9");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-24895");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-24897");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-24936");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29326");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29331");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-32030");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5027107");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5027108");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5027109");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5027110");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5027111");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5027112");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5027113");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5027114");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5027115");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5027116");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5027117");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5027118");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5027119");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5027121");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5027122");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5027123");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5027124");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5027125");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5027126");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5027127");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5027128");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5027129");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5027131");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5027132");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5027133");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5027134");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5027138");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5027139");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5027140");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5027141");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft .NET Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24936");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_dotnet_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "microsoft_net_framework_installed.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('install_func.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

var bulletin = 'MS23-06';
var kbs = make_list(
  '5027107',
  '5027108',
  '5027109',
  '5027110',
  '5027111',
  '5027112',
  '5027113',
  '5027114',
  '5027115',
  '5027116',
  '5027117',
  '5027118',
  '5027119',
  '5027121',
  '5027122',
  '5027123',
  '5027124',
  '5027125',
  '5027126',
  '5027127',
  '5027128',
  '5027129',
  '5027131',
  '5027132',
  '5027133',
  '5027134',
  '5027138',
  '5027139',
  '5027140',
  '5027141'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(vista:'2' , win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

var share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

var app = 'Microsoft .NET Framework';
get_install_count(app_name:app, exit_if_zero:TRUE);
var installs = get_combined_installs(app_name:app);

var install, version;
var vuln = 0;

if (installs[0] == 0)
{
  foreach install (installs[1])
  {
    version = install['version'];
    if( version != UNKNOWN_VER &&
        smb_check_dotnet_rollup(rollup_date:'06_2023', dotnet_ver:version))
      vuln++;
  }
}
if(vuln)
{
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
