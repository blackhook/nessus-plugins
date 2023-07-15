#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(125149);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-11091",
    "CVE-2018-12126",
    "CVE-2018-12127",
    "CVE-2018-12130"
  );
  script_bugtraq_id(108330);
  script_xref(name:"MSKB", value:"4494175");
  script_xref(name:"MSKB", value:"4494452");
  script_xref(name:"MSKB", value:"4494453");
  script_xref(name:"MSKB", value:"4494454");
  script_xref(name:"MSKB", value:"4497165");
  script_xref(name:"MSFT", value:"MS19-4494175");
  script_xref(name:"MSFT", value:"MS19-4494452");
  script_xref(name:"MSFT", value:"MS19-4494453");
  script_xref(name:"MSFT", value:"MS19-4494454");
  script_xref(name:"MSFT", value:"MS19-4497165");
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");
  script_xref(name:"CEA-ID", value:"CEA-2019-0324");

  script_name(english:"Intel Microcode Updates for Windows 10 / Windows Server 2016 / Windows Server 2019 (May 2019) (MDSUM/RIDL) (MFBDS/RIDL/ZombieLoad) (MLPDS/RIDL) (MSBDS/Fallout)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is missing a microcode update.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, missing microcode updates to address the following
vulnerabilities:

  - Microarchitectural Data Sampling Uncacheable Memory (MDSUM) (CVE-2019-11091)
  - Microarchitectural Store Buffer Data Sampling (MSBDS) (CVE-2018-12126)
  - Microarchitectural Load Port Data Sampling (MLPDS) (CVE-2018-12127)
  - Microarchitectural Fill Buffer Data Sampling (MFBDS) (CVE-2018-12130)

Note that Nessus did not actually test for these flaws nor checked the
target processor architecture but instead, has relied on the version
of mcupdate_GenuineIntel.dll to be latest for supported Windows release.");
  # https://support.microsoft.com/en-ie/help/4494175/kb4494175-intel-microcode-updates
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d6715877");
  # https://support.microsoft.com/en-ie/help/4494452/kb4494452-intel-microcode-updates
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c600e5d");
  # https://support.microsoft.com/en-au/help/4494453/kb4494453-intel-microcode-updates
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?16fb167c");
  # https://support.microsoft.com/en-au/help/4494454/kb4494454-intel-microcode-updates
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc221b4a");
  # https://support.microsoft.com/en-au/help/4497165/kb4497165-intel-microcode-updates
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f1b3721e");
  # https://azure.microsoft.com/en-us/blog/securing-azure-customers-from-cpu-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c467280");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Windows 10, Windows Server 2016 and Windows Server 2019.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12126");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "enumerate_ms_azure_vm_win.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible", "Settings/ParanoidReport");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('audit.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('misc_func.inc');
include('smb_reg_query.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (!empty_or_null(get_kb_list("Host/Azure/azure-*")))
  audit(AUDIT_HOST_NOT, "affected");

bulletin = 'MS19-05';

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

get_kb_item_or_exit('SMB/Registry/Enumerated');
ver = get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

# No update for other Windows OS versions, skip testing
if (hotfix_check_sp_range(win10:'0') <= 0)
  exit(0, 'Windows version ' + ver + ' is not tested.');

# No update for version 1511, 1803, 1809 - skip testing
os_build = get_kb_item('SMB/WindowsVersionBuild');
if((os_build == '10586') || (os_build == '17134') || (os_build == '17763'))
  exit(0, 'Windows version ' + ver + ', build ' + os_build + ' is not tested.');

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);
if (
  # RTM
  hotfix_is_vulnerable(os:'10', sp:0, os_build:'10240', file:'mcupdate_genuineintel.dll', version:'10.0.10240.18216', min_version:'10.0.10240.16000', dir:'\\system32', bulletin:bulletin, kb:'4494454') ||

  # 1607
  hotfix_is_vulnerable(os:'10', sp:0, os_build:'14393', file:'mcupdate_genuineintel.dll', version:'10.0.14393.2907', min_version:'10.0.14393.0', dir:'\\system32', bulletin:bulletin, kb:'4494175') ||

  # 1703
  hotfix_is_vulnerable(os:'10', sp:0, os_build:'15063', file:'mcupdate_genuineintel.dll', version:'10.0.15063.1749', min_version:'10.0.15063.0', dir:'\\system32', bulletin:bulletin, kb:'4494453') ||

  # 1709
  hotfix_is_vulnerable(os:'10', sp:0, os_build:'16299', file:'mcupdate_genuineintel.dll', version:'10.0.16299.1091', min_version:'10.0.16299.0', dir:'\\system32', bulletin:bulletin, kb:'4494452') ||

  # 1903
  hotfix_is_vulnerable(os:'10', sp:0, os_build:'18362', file:'mcupdate_genuineintel.dll', version:'10.0.18362.141', min_version:'10.0.18362.0', dir:'\\system32', bulletin:bulletin, kb:'4497165')
)
{
  replace_kb_item(name:'SMB/Missing/' + bulletin, value:TRUE);
  hotfix_security_warning();
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');


