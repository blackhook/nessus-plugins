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
  script_id(167254);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/15");

  script_cve_id("CVE-2022-41064");
  script_xref(name:"MSKB", value:"5020606");
  script_xref(name:"MSKB", value:"5020608");
  script_xref(name:"MSKB", value:"5020609");
  script_xref(name:"MSKB", value:"5020610");
  script_xref(name:"MSKB", value:"5020611");
  script_xref(name:"MSKB", value:"5020612");
  script_xref(name:"MSKB", value:"5020613");
  script_xref(name:"MSKB", value:"5020614");
  script_xref(name:"MSKB", value:"5020615");
  script_xref(name:"MSKB", value:"5020617");
  script_xref(name:"MSKB", value:"5020618");
  script_xref(name:"MSKB", value:"5020619");
  script_xref(name:"MSKB", value:"5020620");
  script_xref(name:"MSKB", value:"5020621");
  script_xref(name:"MSKB", value:"5020622");
  script_xref(name:"MSKB", value:"5020623");
  script_xref(name:"MSKB", value:"5020624");
  script_xref(name:"MSKB", value:"5020627");
  script_xref(name:"MSKB", value:"5020628");
  script_xref(name:"MSKB", value:"5020629");
  script_xref(name:"MSKB", value:"5020630");
  script_xref(name:"MSKB", value:"5020632");
  script_xref(name:"MSFT", value:"MS22-5020606");
  script_xref(name:"MSFT", value:"MS22-5020608");
  script_xref(name:"MSFT", value:"MS22-5020609");
  script_xref(name:"MSFT", value:"MS22-5020610");
  script_xref(name:"MSFT", value:"MS22-5020611");
  script_xref(name:"MSFT", value:"MS22-5020612");
  script_xref(name:"MSFT", value:"MS22-5020613");
  script_xref(name:"MSFT", value:"MS22-5020614");
  script_xref(name:"MSFT", value:"MS22-5020615");
  script_xref(name:"MSFT", value:"MS22-5020617");
  script_xref(name:"MSFT", value:"MS22-5020618");
  script_xref(name:"MSFT", value:"MS22-5020619");
  script_xref(name:"MSFT", value:"MS22-5020620");
  script_xref(name:"MSFT", value:"MS22-5020621");
  script_xref(name:"MSFT", value:"MS22-5020622");
  script_xref(name:"MSFT", value:"MS22-5020623");
  script_xref(name:"MSFT", value:"MS22-5020624");
  script_xref(name:"MSFT", value:"MS22-5020627");
  script_xref(name:"MSFT", value:"MS22-5020628");
  script_xref(name:"MSFT", value:"MS22-5020629");
  script_xref(name:"MSFT", value:"MS22-5020630");
  script_xref(name:"MSFT", value:"MS22-5020632");
  script_xref(name:"IAVA", value:"2022-A-0477-S");

  script_name(english:"Security Updates for Microsoft .NET Framework (November 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update. It is, therefore, affected
by an information disclosure vulnerability in the System.Data.SqlClient and Microsoft.Data.SqlClient packages. A
timeout occurring under high load can cause incorrect data to be returned as the result of an asynchronously
executed query.");
  # https://devblogs.microsoft.com/dotnet/dotnet-framework-november-2022-security-and-quality-rollup-updates/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7499964d");
  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2022-41064
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?893ba2be");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020606");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020608");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020609");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020610");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020611");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020612");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020613");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020614");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020615");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020617");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020618");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020619");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020620");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020621");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020622");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020623");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020624");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020627");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020628");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020629");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020630");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020632");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft .NET Framework.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41064");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var bulletin = 'MS22-11';
var kbs = make_list(
  '5020606',
  '5020608',
  '5020609',
  '5020610',
  '5020611',
  '5020612',
  '5020613',
  '5020614',
  '5020615',
  '5020617',
  '5020618',
  '5020619',
  '5020620',
  '5020621',
  '5020622',
  '5020623',
  '5020624',
  '5020627',
  '5020628',
  '5020629',
  '5020630',
  '5020632'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

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
        smb_check_dotnet_rollup(rollup_date:'11_2022', dotnet_ver:version))
      vuln++;
  }
}
if(vuln)
{
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
