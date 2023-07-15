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
  script_id(140501);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/11");

  script_xref(name:"MSKB", value:"4576478");
  script_xref(name:"MSKB", value:"4576479");
  script_xref(name:"MSKB", value:"4576480");
  script_xref(name:"MSKB", value:"4576481");
  script_xref(name:"MSKB", value:"4576482");
  script_xref(name:"MSKB", value:"4576483");
  script_xref(name:"MSKB", value:"4576484");
  script_xref(name:"MSKB", value:"4576485");
  script_xref(name:"MSKB", value:"4576486");
  script_xref(name:"MSKB", value:"4576487");
  script_xref(name:"MSKB", value:"4576488");
  script_xref(name:"MSKB", value:"4576489");
  script_xref(name:"MSKB", value:"4576490");
  script_xref(name:"MSFT", value:"MS20-4576478");
  script_xref(name:"MSFT", value:"MS20-4576479");
  script_xref(name:"MSFT", value:"MS20-4576480");
  script_xref(name:"MSFT", value:"MS20-4576481");
  script_xref(name:"MSFT", value:"MS20-4576482");
  script_xref(name:"MSFT", value:"MS20-4576483");
  script_xref(name:"MSFT", value:"MS20-4576484");
  script_xref(name:"MSFT", value:"MS20-4576485");
  script_xref(name:"MSFT", value:"MS20-4576486");
  script_xref(name:"MSFT", value:"MS20-4576487");
  script_xref(name:"MSFT", value:"MS20-4576488");
  script_xref(name:"MSFT", value:"MS20-4576489");
  script_xref(name:"MSFT", value:"MS20-4576490");

  script_name(english:"Security Updates for Microsoft .NET Framework (September 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Framework installation on the remote host is missing security updates. The security update addresses 
a potential abuse of ClickOnce to download applications from untrusted servers using NTLM authentication.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4576478/");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4576479/");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4576480/");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4576481/");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4576482/");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4576483/");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4576484/");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4576485/");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4576486/");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4576487/");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4576488/");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4576489/");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4576490/");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft .NET Framework.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = 'MS20-09';
kbs = make_list(
  '4576478',
  '4576479',
  '4576480',
  '4576481',
  '4576482',
  '4576483',
  '4576484',
  '4576485',
  '4576486',
  '4576487',
  '4576488',
  '4576489',
  '4576490'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_NOTE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

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
        smb_check_dotnet_rollup(rollup_date:'09_2020', dotnet_ver:version))
      vuln++;
  }
}
if(vuln)
{
  hotfix_security_note();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
