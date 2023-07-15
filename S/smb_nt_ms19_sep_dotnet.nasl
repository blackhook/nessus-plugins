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
  script_id(128742);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2019-1142");
  script_xref(name:"MSKB", value:"4514355");
  script_xref(name:"MSKB", value:"4514354");
  script_xref(name:"MSKB", value:"4514357");
  script_xref(name:"MSKB", value:"4514356");
  script_xref(name:"MSKB", value:"4514359");
  script_xref(name:"MSKB", value:"4514604");
  script_xref(name:"MSKB", value:"4514603");
  script_xref(name:"MSKB", value:"4514601");
  script_xref(name:"MSKB", value:"4516068");
  script_xref(name:"MSKB", value:"4514599");
  script_xref(name:"MSKB", value:"4516044");
  script_xref(name:"MSKB", value:"4516058");
  script_xref(name:"MSKB", value:"4516070");
  script_xref(name:"MSKB", value:"4516066");
  script_xref(name:"MSKB", value:"4514598");
  script_xref(name:"MSFT", value:"MS19-4514355");
  script_xref(name:"MSFT", value:"MS19-4514354");
  script_xref(name:"MSFT", value:"MS19-4514357");
  script_xref(name:"MSFT", value:"MS19-4514356");
  script_xref(name:"MSFT", value:"MS19-4514359");
  script_xref(name:"MSFT", value:"MS19-4514604");
  script_xref(name:"MSFT", value:"MS19-4514603");
  script_xref(name:"MSFT", value:"MS19-4514601");
  script_xref(name:"MSFT", value:"MS19-4516068");
  script_xref(name:"MSFT", value:"MS19-4514599");
  script_xref(name:"MSFT", value:"MS19-4516044");
  script_xref(name:"MSFT", value:"MS19-4516058");
  script_xref(name:"MSFT", value:"MS19-4516070");
  script_xref(name:"MSFT", value:"MS19-4516066");
  script_xref(name:"MSFT", value:"MS19-4514598");
  script_xref(name:"IAVA", value:"2019-A-0339-S");

  script_name(english:"Security Updates for Microsoft .NET Framework (September 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update. It is,
therefore, affected by an elevation of privilege vulnerability, which exists when the .NET Framework
common language runtime (CLR) allows file creation in arbitrary locations. An attacker who
successfully exploited this vulnerability could write files to folders that require higher
privileges than what the attacker already has.");
  # https://support.microsoft.com/en-us/help/4514355/sep-10-2019-kb4514355-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?27c04222");
  # https://support.microsoft.com/en-us/help/4514354/sep-10-2019-kb4514354-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d723b476");
  # https://support.microsoft.com/en-us/help/4514357/sep-10-2019-kb4514357-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4d02aa2b");
  # https://support.microsoft.com/en-us/help/4514356/sep-10-2019-kb4514356-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1f1fdcfe");
  # https://support.microsoft.com/en-us/help/4514359/sep-10-2019-kb4514359-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a9eb7193");
  # https://support.microsoft.com/en-us/help/4514604/sep-10-2019-kb4514604
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6c93d5dd");
  # https://support.microsoft.com/en-us/help/4514603/sep-10-2019-kb4514603
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9151db74");
  # https://support.microsoft.com/en-us/help/4514601/sep-10-2019-kb4514601-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc693427");
  # https://support.microsoft.com/en-us/help/4516068/windows-10-update-kb4516068
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f71ef8eb");
  # https://support.microsoft.com/en-us/help/4514599/sep-10-2019-kb4514599
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9bddc45f");
  # https://support.microsoft.com/en-us/help/4516044/windows-10-update-kb4516044
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?743596fe");
  # https://support.microsoft.com/en-us/help/4516058/windows-10-update-kb4516058
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d7d71b8f");
  # https://support.microsoft.com/en-us/help/4516070/windows-10-update-kb4516070
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6355fd6e");
  # https://support.microsoft.com/en-us/help/4516066/windows-10-update-kb4516066
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7632e34");
  # https://support.microsoft.com/en-us/help/4514598/sep-10-2019-kb4514598
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f1e01931");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft .NET Framework.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1142");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = 'MS19-09';
kbs = make_list(
  '4514355',
  '4514354',
  '4514357',
  '4514356',
  '4514359',
  '4514604',
  '4514603',
  '4514601',
  '4516068',
  '4514599',
  '4516044',
  '4516058',
  '4516070',
  '4516066',
  '4514598'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_NOTE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

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
        smb_check_dotnet_rollup(rollup_date:'09_2019', dotnet_ver:version))
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

