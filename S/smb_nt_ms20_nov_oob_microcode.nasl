#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(143043);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2018-12126",
    "CVE-2018-12127",
    "CVE-2018-12130",
    "CVE-2019-11091",
    "CVE-2020-8695",
    "CVE-2020-8696",
    "CVE-2020-8698"
  );
  script_xref(name:"MSKB", value:"4589198");
  script_xref(name:"MSKB", value:"4589206");
  script_xref(name:"MSKB", value:"4589208");
  script_xref(name:"MSKB", value:"4589210");
  script_xref(name:"MSKB", value:"4589211");
  script_xref(name:"MSKB", value:"4589212");
  script_xref(name:"MSFT", value:"MS20-4589198");
  script_xref(name:"MSFT", value:"MS20-4589206");
  script_xref(name:"MSFT", value:"MS20-4589208");
  script_xref(name:"MSFT", value:"MS20-4589210");
  script_xref(name:"MSFT", value:"MS20-4589211");
  script_xref(name:"MSFT", value:"MS20-4589212");
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");
  script_xref(name:"CEA-ID", value:"CEA-2019-0324");

  script_name(english:"Security Updates for Windows 10 / Windows Server 2016 / Windows Server 2019 (November 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is missing a microcode update.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, missing microcode updates to address the following
vulnerabilities:

  - Microarchitectural Store Buffer Data Sampling (MSBDS) (CVE-2018-12126).

  - Microarchitectural Load Port Data Sampling (CVE-2018-12127)

  - Intel® Running Average Power Limit (RAPL) Interface (CVE-2020-8695)

Note that Nessus did not actually test for these flaws nor checked the
target processor architecture but instead, has relied on the version
of mcupdate_GenuineIntel.dll to be latest for supported Windows release.");
  # https://support.microsoft.com/en-us/help/4589198/intel-microcode-updates
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?929b2ccf");
  # https://support.microsoft.com/en-us/help/4589206/intel-microcode-updates
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1fffa220");
  # https://support.microsoft.com/en-us/help/4589208/intel-microcode-updates
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42adde49");
  # https://support.microsoft.com/en-us/help/4589210/intel-microcode-updates
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30ff7180");
  # https://support.microsoft.com/en-us/help/4589211/intel-microcode-updates
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fdc1e724");
  # https://support.microsoft.com/en-us/help/4589212/intel-microcode-updates
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?444c0c20");
  # https://azure.microsoft.com/en-us/blog/securing-azure-customers-from-cpu-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c467280");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Windows 10,
Windows Server 2016 and Server 2019.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12126");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "enumerate_ms_azure_vm_win.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible", "Settings/ParanoidReport");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('misc_func.inc');
include('smb_reg_query.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (!empty_or_null(get_kb_list("Host/Azure/azure-*")))
  audit(AUDIT_HOST_NOT, "affected");

bulletin = 'MS20-11';

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

get_kb_item_or_exit('SMB/Registry/Enumerated');
ver = get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

# No update for other Windows OS versions, skip testing
if (hotfix_check_sp_range(win10:'0') <= 0) 
  exit(0, 'Windows version ' + ver + ' is not tested.');

# No update for version 1511, skip testing
os_build = get_kb_item('SMB/WindowsVersionBuild');
if(os_build == '10586')
  exit(0, 'Windows version ' + ver + ', build ' + os_build + ' is not tested.');

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # RTM
  hotfix_is_vulnerable(os:'10', sp:0, os_build:'10240', file:'mcupdate_genuineintel.dll', version:'10.0.10240.18754', min_version:'10.0.10240.16000', dir:'\\system32', bulletin:bulletin, kb:'4589198') ||

  # 1607
  hotfix_is_vulnerable(os:'10', sp:0, os_build:'14393', file:'mcupdate_genuineintel.dll', version:'10.0.14393.4045', min_version:'10.0.14393.0', dir:'\\system32', bulletin:bulletin, kb:'4589210') ||

  # 1803
  hotfix_is_vulnerable(os:'10', sp:0, os_build:'17134', file:'mcupdate_genuineintel.dll', version:'10.0.17134.1844', min_version:'10.0.17134.0', dir:'\\system32', bulletin:bulletin, kb:'4589206') ||

  # 1809
  hotfix_is_vulnerable(os:'10', sp:0, os_build:'17763', file:'mcupdate_genuineintel.dll', version:'10.0.17763.1575', min_version:'10.0.17763.0', dir:'\\system32', bulletin:bulletin, kb:'4589208') ||

  # 1903/1909
  hotfix_is_vulnerable(os:'10', sp:0, os_build:'18362', file:'mcupdate_genuineintel.dll', version:'10.0.18362.1196', min_version:'10.0.18362.0', dir:'\\system32', bulletin:bulletin, kb:'4589211') ||

  # 2004
  hotfix_is_vulnerable(os:'10', sp:0, os_build:'19041', file:'mcupdate_genuineintel.dll', version:'10.0.19041.624', min_version:'10.0.19041.0', dir:'\\system32', bulletin:bulletin, kb:'4589212')
)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  exit(0);
}
else
{
  audit(AUDIT_HOST_NOT, 'affected');
}
