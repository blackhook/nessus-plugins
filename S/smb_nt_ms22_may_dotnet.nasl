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
  script_id(167885);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/21");

  script_cve_id("CVE-2022-30130");
  script_xref(name:"MSKB", value:"5013612");
  script_xref(name:"MSKB", value:"5013615");
  script_xref(name:"MSKB", value:"5013616");
  script_xref(name:"MSKB", value:"5013617");
  script_xref(name:"MSKB", value:"5013618");
  script_xref(name:"MSKB", value:"5013619");
  script_xref(name:"MSKB", value:"5013620");
  script_xref(name:"MSKB", value:"5013621");
  script_xref(name:"MSKB", value:"5013622");
  script_xref(name:"MSKB", value:"5013623");
  script_xref(name:"MSKB", value:"5013624");
  script_xref(name:"MSKB", value:"5013625");
  script_xref(name:"MSKB", value:"5013626");
  script_xref(name:"MSKB", value:"5013627");
  script_xref(name:"MSKB", value:"5013628");
  script_xref(name:"MSKB", value:"5013629");
  script_xref(name:"MSKB", value:"5013630");
  script_xref(name:"MSKB", value:"5013631");
  script_xref(name:"MSKB", value:"5013632");
  script_xref(name:"MSKB", value:"5013635");
  script_xref(name:"MSKB", value:"5013636");
  script_xref(name:"MSKB", value:"5013637");
  script_xref(name:"MSKB", value:"5013638");
  script_xref(name:"MSKB", value:"5013641");
  script_xref(name:"MSKB", value:"5013642");
  script_xref(name:"MSKB", value:"5013643");
  script_xref(name:"MSKB", value:"5013644");
  script_xref(name:"MSFT", value:"MS22-5013612");
  script_xref(name:"MSFT", value:"MS22-5013615");
  script_xref(name:"MSFT", value:"MS22-5013616");
  script_xref(name:"MSFT", value:"MS22-5013617");
  script_xref(name:"MSFT", value:"MS22-5013618");
  script_xref(name:"MSFT", value:"MS22-5013619");
  script_xref(name:"MSFT", value:"MS22-5013620");
  script_xref(name:"MSFT", value:"MS22-5013621");
  script_xref(name:"MSFT", value:"MS22-5013622");
  script_xref(name:"MSFT", value:"MS22-5013623");
  script_xref(name:"MSFT", value:"MS22-5013624");
  script_xref(name:"MSFT", value:"MS22-5013625");
  script_xref(name:"MSFT", value:"MS22-5013626");
  script_xref(name:"MSFT", value:"MS22-5013627");
  script_xref(name:"MSFT", value:"MS22-5013628");
  script_xref(name:"MSFT", value:"MS22-5013629");
  script_xref(name:"MSFT", value:"MS22-5013630");
  script_xref(name:"MSFT", value:"MS22-5013631");
  script_xref(name:"MSFT", value:"MS22-5013632");
  script_xref(name:"MSFT", value:"MS22-5013635");
  script_xref(name:"MSFT", value:"MS22-5013636");
  script_xref(name:"MSFT", value:"MS22-5013637");
  script_xref(name:"MSFT", value:"MS22-5013638");
  script_xref(name:"MSFT", value:"MS22-5013641");
  script_xref(name:"MSFT", value:"MS22-5013642");
  script_xref(name:"MSFT", value:"MS22-5013643");
  script_xref(name:"MSFT", value:"MS22-5013644");
  script_xref(name:"IAVA", value:"2022-A-0202-S");

  script_name(english:"Security Updates for Microsoft .NET Framework (May 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update. It is, therefore, affected
by a denial of service vulnerability that is caused by a local user opening a specially crafted file.");
  # https://devblogs.microsoft.com/dotnet/framework-may-2022-updates/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?688c69af");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30130
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba7b56f2");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5013612");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5013615");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5013616");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5013617");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5013618");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5013619");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5013620");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5013621");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5013622");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5013623");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5013624");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5013625");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5013626");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5013627");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5013628");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5013629");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5013630");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5013631");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5013632");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5013635");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5013636");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5013637");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5013638");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5013641");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5013642");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5013643");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5013644");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft .NET Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-30130");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/18");

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

var bulletin = 'MS22-05';
var kbs = make_list(
  '5013612',
  '5013615',
  '5013616',
  '5013617',
  '5013618',
  '5013619',
  '5013620',
  '5013621',
  '5013622',
  '5013623',
  '5013624',
  '5013625',
  '5013626',
  '5013627',
  '5013628',
  '5013629',
  '5013630',
  '5013631',
  '5013632',
  '5013635',
  '5013636',
  '5013637',
  '5013638',
  '5013641',
  '5013642',
  '5013643',
  '5013644'
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
        smb_check_dotnet_rollup(rollup_date:'05_2022', dotnet_ver:version))
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
