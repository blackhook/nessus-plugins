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
  script_id(139598);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2020-1046", "CVE-2020-1476");
  script_xref(name:"MSKB", value:"4569751");
  script_xref(name:"MSKB", value:"4571709");
  script_xref(name:"MSKB", value:"4569748");
  script_xref(name:"MSKB", value:"4569749");
  script_xref(name:"MSKB", value:"4569746");
  script_xref(name:"MSKB", value:"4571692");
  script_xref(name:"MSKB", value:"4569745");
  script_xref(name:"MSKB", value:"4571741");
  script_xref(name:"MSKB", value:"4570506");
  script_xref(name:"MSKB", value:"4570507");
  script_xref(name:"MSKB", value:"4571694");
  script_xref(name:"MSKB", value:"4570505");
  script_xref(name:"MSKB", value:"4570502");
  script_xref(name:"MSKB", value:"4570503");
  script_xref(name:"MSKB", value:"4570500");
  script_xref(name:"MSKB", value:"4570501");
  script_xref(name:"MSKB", value:"4570508");
  script_xref(name:"MSKB", value:"4570509");
  script_xref(name:"MSFT", value:"MS20-4569751");
  script_xref(name:"MSFT", value:"MS20-4571709");
  script_xref(name:"MSFT", value:"MS20-4569748");
  script_xref(name:"MSFT", value:"MS20-4569749");
  script_xref(name:"MSFT", value:"MS20-4569746");
  script_xref(name:"MSFT", value:"MS20-4571692");
  script_xref(name:"MSFT", value:"MS20-4569745");
  script_xref(name:"MSFT", value:"MS20-4571741");
  script_xref(name:"MSFT", value:"MS20-4570506");
  script_xref(name:"MSFT", value:"MS20-4570507");
  script_xref(name:"MSFT", value:"MS20-4571694");
  script_xref(name:"MSFT", value:"MS20-4570505");
  script_xref(name:"MSFT", value:"MS20-4570502");
  script_xref(name:"MSFT", value:"MS20-4570503");
  script_xref(name:"MSFT", value:"MS20-4570500");
  script_xref(name:"MSFT", value:"MS20-4570501");
  script_xref(name:"MSFT", value:"MS20-4570508");
  script_xref(name:"MSFT", value:"MS20-4570509");
  script_xref(name:"IAVA", value:"2020-A-0368-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0101");

  script_name(english:"Security Updates for Microsoft .NET Framework (August 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET Framework installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Framework installation on the remote host
is missing security updates. It is, therefore, affected by
multiple vulnerabilities :

  - An elevation of privilege vulnerability exists when
    ASP.NET or .NET web applications running on IIS
    improperly allow access to cached files. An attacker who
    successfully exploited this vulnerability could gain
    access to restricted files.  (CVE-2020-1476)

  - A remote code execution vulnerability exists when
    Microsoft .NET Framework processes input. An attacker
    who successfully exploited this vulnerability could take
    control of an affected system.  (CVE-2020-1046)");
  # https://support.microsoft.com/en-us/help/4569751/kb4569751-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?19866103");
  # https://support.microsoft.com/en-us/help/4571709/windows-10-update-kb4571709
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3c857b4");
  # https://support.microsoft.com/en-us/help/4569748/kb4569748-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?27215a0a");
  # https://support.microsoft.com/en-us/help/4569749/kb4569749-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1f113aae");
  # https://support.microsoft.com/en-us/help/4569746/kb4569746-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5a5cf10b");
  # https://support.microsoft.com/en-us/help/4571692/windows-10-update-kb4571692
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?481aa152");
  # https://support.microsoft.com/en-us/help/4569745/kb4569745-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?af841f22");
  # https://support.microsoft.com/en-us/help/4571741/windows-10-update-kb4571741
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9371bc74");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4570506/kb4570506");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4570507/kb4570507");
  # https://support.microsoft.com/en-us/help/4571694/windows-10-update-kb4571694
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1446acfc");
  # https://support.microsoft.com/en-us/help/4570505/kb4570505-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4b0beccb");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4570502/kb4570502");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4570503/kb4570503");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4570500/kb4570500");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4570501/kb4570501");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4570508/kb4570508");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4570509/kb4570509");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft .NET Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1046");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = 'MS20-08';
kbs = make_list(
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

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
        smb_check_dotnet_rollup(rollup_date:'08_2020', dotnet_ver:version))
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



