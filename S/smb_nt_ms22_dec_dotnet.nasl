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
  script_id(168745);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/16");

  script_cve_id("CVE-2022-41089");
  script_xref(name:"MSKB", value:"5020859");
  script_xref(name:"MSKB", value:"5020860");
  script_xref(name:"MSKB", value:"5020861");
  script_xref(name:"MSKB", value:"5020862");
  script_xref(name:"MSKB", value:"5020866");
  script_xref(name:"MSKB", value:"5020867");
  script_xref(name:"MSKB", value:"5020868");
  script_xref(name:"MSKB", value:"5020869");
  script_xref(name:"MSKB", value:"5020872");
  script_xref(name:"MSKB", value:"5020873");
  script_xref(name:"MSKB", value:"5020874");
  script_xref(name:"MSKB", value:"5020875");
  script_xref(name:"MSKB", value:"5020876");
  script_xref(name:"MSKB", value:"5020877");
  script_xref(name:"MSKB", value:"5020878");
  script_xref(name:"MSKB", value:"5020879");
  script_xref(name:"MSKB", value:"5020880");
  script_xref(name:"MSKB", value:"5020881");
  script_xref(name:"MSKB", value:"5020882");
  script_xref(name:"MSKB", value:"5020883");
  script_xref(name:"MSKB", value:"5020894");
  script_xref(name:"MSKB", value:"5020895");
  script_xref(name:"MSKB", value:"5020896");
  script_xref(name:"MSKB", value:"5020897");
  script_xref(name:"MSKB", value:"5020898");
  script_xref(name:"MSKB", value:"5020899");
  script_xref(name:"MSKB", value:"5020900");
  script_xref(name:"MSKB", value:"5020901");
  script_xref(name:"MSKB", value:"5020902");
  script_xref(name:"MSKB", value:"5020903");
  script_xref(name:"MSFT", value:"MS22-5020859");
  script_xref(name:"MSFT", value:"MS22-5020860");
  script_xref(name:"MSFT", value:"MS22-5020861");
  script_xref(name:"MSFT", value:"MS22-5020862");
  script_xref(name:"MSFT", value:"MS22-5020866");
  script_xref(name:"MSFT", value:"MS22-5020867");
  script_xref(name:"MSFT", value:"MS22-5020868");
  script_xref(name:"MSFT", value:"MS22-5020869");
  script_xref(name:"MSFT", value:"MS22-5020872");
  script_xref(name:"MSFT", value:"MS22-5020873");
  script_xref(name:"MSFT", value:"MS22-5020874");
  script_xref(name:"MSFT", value:"MS22-5020875");
  script_xref(name:"MSFT", value:"MS22-5020876");
  script_xref(name:"MSFT", value:"MS22-5020877");
  script_xref(name:"MSFT", value:"MS22-5020878");
  script_xref(name:"MSFT", value:"MS22-5020879");
  script_xref(name:"MSFT", value:"MS22-5020880");
  script_xref(name:"MSFT", value:"MS22-5020881");
  script_xref(name:"MSFT", value:"MS22-5020882");
  script_xref(name:"MSFT", value:"MS22-5020883");
  script_xref(name:"MSFT", value:"MS22-5020894");
  script_xref(name:"MSFT", value:"MS22-5020895");
  script_xref(name:"MSFT", value:"MS22-5020896");
  script_xref(name:"MSFT", value:"MS22-5020897");
  script_xref(name:"MSFT", value:"MS22-5020898");
  script_xref(name:"MSFT", value:"MS22-5020899");
  script_xref(name:"MSFT", value:"MS22-5020900");
  script_xref(name:"MSFT", value:"MS22-5020901");
  script_xref(name:"MSFT", value:"MS22-5020902");
  script_xref(name:"MSFT", value:"MS22-5020903");
  script_xref(name:"IAVA", value:"2022-A-0534-S");

  script_name(english:"Security Updates for Microsoft .NET Framework (December 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update. It is, therefore, affected
by a remote code execution vulnerability in the handling of XPS files.");
  # https://devblogs.microsoft.com/dotnet/dotnet-framework-december-2022-security-and-quality-rollup-updates/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d29de7c");
  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2022-41089
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e40dadbd");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020859");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020860");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020861");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020862");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020866");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020867");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020868");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020869");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020872");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020873");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020874");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020875");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020876");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020877");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020878");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020879");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020880");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020881");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020882");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020883");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020894");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020895");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020896");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020897");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020898");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020899");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020900");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020901");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020902");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020903");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft .NET Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41089");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var bulletin = 'MS22-12';
var kbs = make_list(
  '5020859',
  '5020860',
  '5020861',
  '5020862',
  '5020866',
  '5020867',
  '5020868',
  '5020869',
  '5020872',
  '5020873',
  '5020874',
  '5020875',
  '5020876',
  '5020877',
  '5020878',
  '5020879',
  '5020880',
  '5020881',
  '5020882',
  '5020883',
  '5020894',
  '5020895',
  '5020896',
  '5020897',
  '5020898',
  '5020899',
  '5020900',
  '5020901',
  '5020902',
  '5020903'
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
        smb_check_dotnet_rollup(rollup_date:'12_2022', dotnet_ver:version))
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
