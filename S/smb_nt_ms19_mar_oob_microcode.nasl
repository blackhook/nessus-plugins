#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(122975);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/15");

  script_cve_id(
    "CVE-2018-3620",
    "CVE-2018-3639",
    "CVE-2018-3640",
    "CVE-2018-3646"
  );
  script_bugtraq_id(104228, 104232, 105080);
  script_xref(name:"MSKB", value:"4465065");
  script_xref(name:"MSKB", value:"4346084");
  script_xref(name:"MSKB", value:"4346085");
  script_xref(name:"MSKB", value:"4346086");
  script_xref(name:"MSKB", value:"4346087");
  script_xref(name:"MSKB", value:"4346088");
  script_xref(name:"MSFT", value:"MS19-4465065");
  script_xref(name:"MSFT", value:"MS19-4346084");
  script_xref(name:"MSFT", value:"MS19-4346085");
  script_xref(name:"MSFT", value:"MS19-4346086");
  script_xref(name:"MSFT", value:"MS19-4346087");
  script_xref(name:"MSFT", value:"MS19-4346088");

  script_name(english:"Security Updates for Windows 10 / Windows Server 2016 / Windows Server 2019 (March 2019) (Spectre) (Meltdown) (Foreshadow)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is missing a microcode update.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, missing microcode updates to address the following
vulnerabilities:

  - Spectre Variant 3a (CVE-2018-3640: Rogue System Register Read (RSRE)).

  - Spectre Variant 4 (CVE-2018-3639: Speculative Store Bypass (SSB))

  - L1TF (CVE-2018-3620, CVE-2018-3646: L1 Terminal Fault)

Note that Nessus did not actually test for these flaws nor checked the
target processor architecture but instead, has relied on the version
of mcupdate_GenuineIntel.dll to be latest for supported Windows release.");
  # https://support.microsoft.com/en-ie/help/4465065/kb4465065-intel-microcode-updates
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6b54af4a");
  # https://support.microsoft.com/en-ie/help/4346084/kb4346084-intel-microcode-updates
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2d0e32dc");
  # https://support.microsoft.com/en-us/help/4346085/kb4346085-intel-microcode-updates
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91f9cc84");
  # https://support.microsoft.com/en-ie/help/4346086/kb4346086-intel-microcode-updates
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?236ac8ce");
  # https://support.microsoft.com/en-au/help/4346087/kb4346087-intel-microcode-updates
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bcc8c14e");
  # https://support.microsoft.com/en-ie/help/4346088/kb4346088-intel-microcode-updates
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?826f213e");
  # https://azure.microsoft.com/en-us/blog/securing-azure-customers-from-cpu-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c467280");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Windows 10,
Windows Server 2016 and Server 2019.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3646");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "enumerate_ms_azure_vm_win.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible", "Settings/ParanoidReport");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("smb_reg_query.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (!empty_or_null(get_kb_list("Host/Azure/azure-*")))
  audit(AUDIT_HOST_NOT, "affected");

bulletin = 'MS19-03';

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

get_kb_item_or_exit("SMB/Registry/Enumerated");
ver = get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

# No update for other Windows OS versions, skip testing
if (hotfix_check_sp_range(win10:'0') <= 0) 
  exit(0, "Windows version " + ver + " is not tested.");

# No update for version 1511, skip testing
os_build = get_kb_item("SMB/WindowsVersionBuild");
if(os_build == "10586")
  exit(0, "Windows version " + ver + ", build " + os_build + " is not tested.");

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # RTM
  hotfix_is_vulnerable(os:"10", sp:0, os_build:"10240", file:"mcupdate_genuineintel.dll", version:"10.0.10240.18151", min_version:"10.0.10240.16000", dir:"\system32", bulletin:bulletin, kb:"4346088") ||

  # 1607
  hotfix_is_vulnerable(os:"10", sp:0, os_build:"14393", file:"mcupdate_genuineintel.dll", version:"10.0.14393.2842", min_version:"10.0.14393.0", dir:"\system32", bulletin:bulletin, kb:"4346087") ||

  # 1703
  hotfix_is_vulnerable(os:"10", sp:0, os_build:"15063", file:"mcupdate_genuineintel.dll", version:"10.0.15063.1681", min_version:"10.0.15063.0", dir:"\system32", bulletin:bulletin, kb:"4346086") ||

  # 1709
  hotfix_is_vulnerable(os:"10", sp:0, os_build:"16299", file:"mcupdate_genuineintel.dll", version:"10.0.16299.1022", min_version:"10.0.16299.0", dir:"\system32", bulletin:bulletin, kb:"4346085") ||

  # 1803
  hotfix_is_vulnerable(os:"10", sp:0, os_build:"17134", file:"mcupdate_genuineintel.dll", version:"10.0.17134.641", min_version:"10.0.17134.0", dir:"\system32", bulletin:bulletin, kb:"4346084") ||

  # 1809
  hotfix_is_vulnerable(os:"10", sp:0, os_build:"17763", file:"mcupdate_genuineintel.dll", version:"10.0.17763.370", min_version:"10.0.17763.0", dir:"\system32", bulletin:bulletin, kb:"4465065")
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
