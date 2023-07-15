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
  script_id(168397);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2022-21911");
  script_xref(name:"MSKB", value:"5008858");
  script_xref(name:"MSKB", value:"5008859");
  script_xref(name:"MSKB", value:"5008860");
  script_xref(name:"MSKB", value:"5008865");
  script_xref(name:"MSKB", value:"5008866");
  script_xref(name:"MSKB", value:"5008867");
  script_xref(name:"MSKB", value:"5008868");
  script_xref(name:"MSKB", value:"5008869");
  script_xref(name:"MSKB", value:"5008870");
  script_xref(name:"MSKB", value:"5008873");
  script_xref(name:"MSKB", value:"5008874");
  script_xref(name:"MSKB", value:"5008875");
  script_xref(name:"MSKB", value:"5008876");
  script_xref(name:"MSKB", value:"5008877");
  script_xref(name:"MSKB", value:"5008878");
  script_xref(name:"MSKB", value:"5008879");
  script_xref(name:"MSKB", value:"5008880");
  script_xref(name:"MSKB", value:"5008881");
  script_xref(name:"MSKB", value:"5008882");
  script_xref(name:"MSKB", value:"5008883");
  script_xref(name:"MSKB", value:"5008885");
  script_xref(name:"MSKB", value:"5008886");
  script_xref(name:"MSKB", value:"5008887");
  script_xref(name:"MSKB", value:"5008888");
  script_xref(name:"MSKB", value:"5008889");
  script_xref(name:"MSKB", value:"5008890");
  script_xref(name:"MSKB", value:"5008891");
  script_xref(name:"MSKB", value:"5008892");
  script_xref(name:"MSKB", value:"5008893");
  script_xref(name:"MSKB", value:"5008894");
  script_xref(name:"MSKB", value:"5008895");
  script_xref(name:"MSKB", value:"5008896");
  script_xref(name:"MSKB", value:"5008897");
  script_xref(name:"MSFT", value:"MS22-5008858");
  script_xref(name:"MSFT", value:"MS22-5008859");
  script_xref(name:"MSFT", value:"MS22-5008860");
  script_xref(name:"MSFT", value:"MS22-5008865");
  script_xref(name:"MSFT", value:"MS22-5008866");
  script_xref(name:"MSFT", value:"MS22-5008867");
  script_xref(name:"MSFT", value:"MS22-5008868");
  script_xref(name:"MSFT", value:"MS22-5008869");
  script_xref(name:"MSFT", value:"MS22-5008870");
  script_xref(name:"MSFT", value:"MS22-5008873");
  script_xref(name:"MSFT", value:"MS22-5008874");
  script_xref(name:"MSFT", value:"MS22-5008875");
  script_xref(name:"MSFT", value:"MS22-5008876");
  script_xref(name:"MSFT", value:"MS22-5008877");
  script_xref(name:"MSFT", value:"MS22-5008878");
  script_xref(name:"MSFT", value:"MS22-5008879");
  script_xref(name:"MSFT", value:"MS22-5008880");
  script_xref(name:"MSFT", value:"MS22-5008881");
  script_xref(name:"MSFT", value:"MS22-5008882");
  script_xref(name:"MSFT", value:"MS22-5008883");
  script_xref(name:"MSFT", value:"MS22-5008885");
  script_xref(name:"MSFT", value:"MS22-5008886");
  script_xref(name:"MSFT", value:"MS22-5008887");
  script_xref(name:"MSFT", value:"MS22-5008888");
  script_xref(name:"MSFT", value:"MS22-5008889");
  script_xref(name:"MSFT", value:"MS22-5008890");
  script_xref(name:"MSFT", value:"MS22-5008891");
  script_xref(name:"MSFT", value:"MS22-5008892");
  script_xref(name:"MSFT", value:"MS22-5008893");
  script_xref(name:"MSFT", value:"MS22-5008894");
  script_xref(name:"MSFT", value:"MS22-5008895");
  script_xref(name:"MSFT", value:"MS22-5008896");
  script_xref(name:"MSFT", value:"MS22-5008897");

  script_name(english:"Security Updates for Microsoft .NET Framework (January 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update. It is, therefore, affected
by a denial of service vulnerability.");
  # https://devblogs.microsoft.com/dotnet/net-framework-january-2022-security-and-quality-rollup-updates/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a191b934");
  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2022-21911
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0717522a");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008858");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008859");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008860");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008865");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008866");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008867");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008868");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008869");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008870");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008873");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008874");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008875");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008876");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008877");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008878");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008879");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008880");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008881");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008882");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008883");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008885");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008886");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008887");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008888");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008889");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008890");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008891");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008892");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008893");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008894");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008895");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008896");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008897");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft .NET Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21911");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
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

var bulletin = 'MS22-01';
var kbs = make_list(
  '5008858',
  '5008859',
  '5008860',
  '5008865',
  '5008866',
  '5008867',
  '5008868',
  '5008869',
  '5008870',
  '5008873',
  '5008874',
  '5008875',
  '5008876',
  '5008877',
  '5008878',
  '5008879',
  '5008880',
  '5008881',
  '5008882',
  '5008883',
  '5008885',
  '5008886',
  '5008887',
  '5008888',
  '5008889',
  '5008890',
  '5008891',
  '5008892',
  '5008893',
  '5008894',
  '5008895',
  '5008896',
  '5008897'
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
        smb_check_dotnet_rollup(rollup_date:'01_2022', dotnet_ver:version))
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
