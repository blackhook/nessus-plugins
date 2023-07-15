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
  script_id(141503);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-16937");
  script_xref(name:"MSKB", value:"4578968");
  script_xref(name:"MSKB", value:"4578969");
  script_xref(name:"MSKB", value:"4578971");
  script_xref(name:"MSKB", value:"4578972");
  script_xref(name:"MSKB", value:"4578974");
  script_xref(name:"MSKB", value:"4579976");
  script_xref(name:"MSKB", value:"4579977");
  script_xref(name:"MSKB", value:"4579978");
  script_xref(name:"MSKB", value:"4579979");
  script_xref(name:"MSKB", value:"4579980");
  script_xref(name:"MSKB", value:"4580327");
  script_xref(name:"MSKB", value:"4580328");
  script_xref(name:"MSKB", value:"4580330");
  script_xref(name:"MSKB", value:"4580346");
  script_xref(name:"MSKB", value:"4580467");
  script_xref(name:"MSKB", value:"4580468");
  script_xref(name:"MSKB", value:"4580469");
  script_xref(name:"MSKB", value:"4580470");
  script_xref(name:"MSFT", value:"MS20-4578968");
  script_xref(name:"MSFT", value:"MS20-4578969");
  script_xref(name:"MSFT", value:"MS20-4578971");
  script_xref(name:"MSFT", value:"MS20-4578972");
  script_xref(name:"MSFT", value:"MS20-4578974");
  script_xref(name:"MSFT", value:"MS20-4579976");
  script_xref(name:"MSFT", value:"MS20-4579977");
  script_xref(name:"MSFT", value:"MS20-4579978");
  script_xref(name:"MSFT", value:"MS20-4579979");
  script_xref(name:"MSFT", value:"MS20-4579980");
  script_xref(name:"MSFT", value:"MS20-4580327");
  script_xref(name:"MSFT", value:"MS20-4580328");
  script_xref(name:"MSFT", value:"MS20-4580330");
  script_xref(name:"MSFT", value:"MS20-4580346");
  script_xref(name:"MSFT", value:"MS20-4580467");
  script_xref(name:"MSFT", value:"MS20-4580468");
  script_xref(name:"MSFT", value:"MS20-4580469");
  script_xref(name:"MSFT", value:"MS20-4580470");
  script_xref(name:"IAVA", value:"2020-A-0456-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0126");

  script_name(english:"Security Updates for Microsoft .NET Framework (October 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Framework installation on the remote host
is missing a security update. It is, therefore, affected by
the following vulnerability :

  - An information disclosure vulnerability exists when the
    .NET Framework improperly handles objects in memory. An
    attacker who successfully exploited the vulnerability
    could disclose contents of an affected system's memory.
    (CVE-2020-16937)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4578968");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4578969");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4578971");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4578972");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4578974");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4579976");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4579977");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4579978");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4579979");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4579980");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4580327");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4580328");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4580330");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4580346");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4580467");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4580468");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4580469");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4580470");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft .NET Framework.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_dotnet_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "microsoft_net_framework_installed.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('install_func.inc');
include('misc_func.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS20-10';
kbs = make_list(
  '4578968',
  '4578969',
  '4578971',
  '4578972',
  '4578974',
  '4579976',
  '4579977',
  '4579978',
  '4579979',
  '4579980',
  '4580327',
  '4580328',
  '4580330',
  '4580346',
  '4580467',
  '4580468',
  '4580469',
  '4580470'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(vista:'2' , win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit('SMB/ProductName', exit_code:1);
if ('Windows 8' >< productname && 'Windows 8.1' >!< productname) audit(AUDIT_OS_SP_NOT_VULN);
else if ('Vista' >< productname) audit(AUDIT_OS_SP_NOT_VULN);

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
        smb_check_dotnet_rollup(rollup_date:'10_2020', dotnet_ver:version))
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
