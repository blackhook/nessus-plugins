#
# (C) Tenable Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(112116);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/19");

  script_cve_id(
    "CVE-2018-3615",
    "CVE-2018-3620",
    "CVE-2018-3639",
    "CVE-2018-3640",
    "CVE-2018-3646"
  );
  script_bugtraq_id(
    104228,
    104232,
    105080
  );
  script_xref(name:"MSKB", value:"4346084");
  script_xref(name:"MSKB", value:"4346085");
  script_xref(name:"MSKB", value:"4346086");
  script_xref(name:"MSKB", value:"4346087");
  script_xref(name:"MSKB", value:"4346088");
  script_xref(name:"MSFT", value:"MS18-4346084");
  script_xref(name:"MSFT", value:"MS18-4346085");
  script_xref(name:"MSFT", value:"MS18-4346086");
  script_xref(name:"MSFT", value:"MS18-4346087");
  script_xref(name:"MSFT", value:"MS18-4346088");

  script_name(english:"Security Updates for Windows 10 / Windows Server 2016 (August 2018) (Spectre) (Meltdown) (Foreshadow)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is missing a microcode update.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, missing microcode updates to address Rogue System Register
Read (RSRE), Speculative Store Bypass (SSB), L1 Terminal Fault (L1TF),
and Branch Target Injection vulnerabilities.");
  #https://support.microsoft.com/en-us/help/4346084/kb4346084-intel-microcode-updates
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f269f807");
  #https://support.microsoft.com/en-us/help/4346085/kb4346085-intel-microcode-updates
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91f9cc84");
  #https://support.microsoft.com/en-us/help/4346086/kb4346086-intel-microcode-updates
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?48c16e64");
  #https://support.microsoft.com/en-us/help/4346087/kb4346087-intel-microcode-updates
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?31322060");
  #https://support.microsoft.com/en-us/help/4346088/kb4346088-intel-microcode-updates
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cd4345c3");
  # https://azure.microsoft.com/en-us/blog/securing-azure-customers-from-cpu-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c467280");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Windows 10 and Windows Server 2016.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3615");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "enumerate_ms_azure_vm_win.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("smb_reg_query.inc");

if (!empty_or_null(get_kb_list("Host/Azure/azure-*")))
  audit(AUDIT_HOST_NOT, "affected");

bulletin = 'MS18-08';

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # RTM
  hotfix_is_vulnerable(os:"10", sp:0, os_build:"10240", file:"mcupdate_genuineintel.dll", version:"10.0.10240.17944", min_version:"10.0.10240.16000", dir:"\system32", bulletin:bulletin, kb:"4346088") ||

    # 1607
  hotfix_is_vulnerable(os:"10", sp:0, os_build:"14393", file:"mcupdate_genuineintel.dll", version:"10.0.14393.2453", min_version:"10.0.14393.0", dir:"\system32", bulletin:bulletin, kb:"4346087") ||

    # 1703
  hotfix_is_vulnerable(os:"10", sp:0, os_build:"15063", file:"mcupdate_genuineintel.dll", version:"10.0.15063.1292", min_version:"10.0.15063.0", dir:"\system32", bulletin:bulletin, kb:"4346086") ||

    # 1709
  hotfix_is_vulnerable(os:"10", sp:0, os_build:"16299", file:"mcupdate_genuineintel.dll", version:"10.0.16299.636", min_version:"10.0.16299.0", dir:"\system32", bulletin:bulletin, kb:"4346085") ||

    # 1803
  hotfix_is_vulnerable(os:"10", sp:0, os_build:"17134", file:"mcupdate_genuineintel.dll", version:"10.0.17134.253", min_version:"10.0.17134.0", dir:"\system32", bulletin:bulletin, kb:"4346084")
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
