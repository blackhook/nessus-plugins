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
  script_id(105731);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2018-0764", "CVE-2018-0786");
  script_bugtraq_id(102380, 102387);
  script_xref(name:"MSKB", value:"4054170");
  script_xref(name:"MSKB", value:"4054171");
  script_xref(name:"MSKB", value:"4054172");
  script_xref(name:"MSKB", value:"4054174");
  script_xref(name:"MSKB", value:"4054175");
  script_xref(name:"MSKB", value:"4054176");
  script_xref(name:"MSKB", value:"4054177");
  script_xref(name:"MSKB", value:"4054181");
  script_xref(name:"MSKB", value:"4054182");
  script_xref(name:"MSKB", value:"4054183");
  script_xref(name:"MSKB", value:"4054993");
  script_xref(name:"MSKB", value:"4054994");
  script_xref(name:"MSKB", value:"4054995");
  script_xref(name:"MSKB", value:"4054996");
  script_xref(name:"MSKB", value:"4054997");
  script_xref(name:"MSKB", value:"4054998");
  script_xref(name:"MSKB", value:"4054999");
  script_xref(name:"MSKB", value:"4055000");
  script_xref(name:"MSKB", value:"4055001");
  script_xref(name:"MSKB", value:"4055002");
  script_xref(name:"MSKB", value:"4055266");
  script_xref(name:"MSFT", value:"MS18-4054170");
  script_xref(name:"MSFT", value:"MS18-4054171");
  script_xref(name:"MSFT", value:"MS18-4054172");
  script_xref(name:"MSFT", value:"MS18-4054174");
  script_xref(name:"MSFT", value:"MS18-4054175");
  script_xref(name:"MSFT", value:"MS18-4054176");
  script_xref(name:"MSFT", value:"MS18-4054177");
  script_xref(name:"MSFT", value:"MS18-4054181");
  script_xref(name:"MSFT", value:"MS18-4054182");
  script_xref(name:"MSFT", value:"MS18-4054183");
  script_xref(name:"MSFT", value:"MS18-4054993");
  script_xref(name:"MSFT", value:"MS18-4054994");
  script_xref(name:"MSFT", value:"MS18-4054995");
  script_xref(name:"MSFT", value:"MS18-4054996");
  script_xref(name:"MSFT", value:"MS18-4054997");
  script_xref(name:"MSFT", value:"MS18-4054998");
  script_xref(name:"MSFT", value:"MS18-4054999");
  script_xref(name:"MSFT", value:"MS18-4055000");
  script_xref(name:"MSFT", value:"MS18-4055001");
  script_xref(name:"MSFT", value:"MS18-4055002");
  script_xref(name:"MSFT", value:"MS18-4055266");

  script_name(english:"Security and Quality Rollup for .NET Framework (January 2018)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a software framework installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The .NET Framework installation on the remote host is missing a
security update. It is, therefore, affected by the following
vulnerabilities:

  - A Denial of Service vulnerability exists when .NET, and
    .NET core, improperly process XML documents. An attacker
    who successfully exploited this vulnerability could
    cause a denial of service against a .NET application. A
    remote unauthenticated attacker could exploit this
    vulnerability by issuing specially crafted requests to a
    .NET(or .NET core) application. (CVE-2018-0764)

  - A security feature bypass vulnerability exists when
    Microsoft .NET Framework (and .NET Core) components do
    not completely validate certificates. An attacker could
    present a certificate that is marked invalid for a
    specific use, but the component uses it for that
    purpose. This action disregards the Enhanced Key Usage
    taggings. (CVE-2018-0786)");
  # https://portal.msrc.microsoft.com/en-us/security-guidance/releasenotedetail/858123b8-25ca-e711-a957-000d3a33cf99
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cb615d29");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-0764
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf7d5ce3");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-0786
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3759d74b");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft .NET Framework
2.0 SP2, 3.5, 3.5.1, 4.5.2, 4.6, 4.6.1, 4.6.2, 4.7, and 4.7.1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0786");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_dotnet_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "microsoft_net_framework_installed.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = "MS18-01";
kbs = make_list(
  '4054170',
  '4054171',
  '4054172',
  '4054174',
  '4054175',
  '4054176',
  '4054177',
  '4054181',
  '4054182',
  '4054183',
  '4054993',
  '4054994',
  '4054995',
  '4054996',
  '4054997',
  '4054998',
  '4054999',
  '4055000',
  '4055001',
  '4055002',
  '4055266'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "Windows 8.1" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);
else if ("Vista" >< productname) audit(AUDIT_OS_SP_NOT_VULN);
else if ("Windows 10" >< productname) audit(AUDIT_OS_SP_NOT_VULN);
else if ("Server 2016" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

app = 'Microsoft .NET Framework';
get_install_count(app_name:app, exit_if_zero:TRUE);
installs = get_combined_installs(app_name:app);

vuln = 0;

if (installs[0] == 0)
{
  foreach install (installs[1])
  {
    version = install['version'];
    if( version != UNKNOWN_VER &&
        smb_check_dotnet_rollup(rollup_date:"01_2018", dotnet_ver:version))
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
  audit(AUDIT_HOST_NOT, "affected");
}
