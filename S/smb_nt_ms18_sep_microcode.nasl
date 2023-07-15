#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(119239);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/20");

  script_cve_id("CVE-2017-5715");
  script_xref(name:"MSKB", value:"4091664");
  script_xref(name:"MSFT", value:"MS18-4091664");

  script_name(english:"Security Updates for Windows 10 / Windows Server 2016 (September 2018) (Spectre)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is missing a microcode update.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, missing microcode updates to address Spectre Variant 2 (CVE-2017-5715: 
Branch Target Injection) vulnerability.");
  # https://support.microsoft.com/en-ca/help/4091664/kb4091664-intel-microcode-updates
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cd8152ab");
  # https://azure.microsoft.com/en-us/blog/securing-azure-customers-from-cpu-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c467280");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Windows 10 and Windows Server 2016.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5715");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
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

bulletin = 'MS18-09';

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # 1607
  hotfix_is_vulnerable(os:"10", sp:0, os_build:"14393", file:"mcupdate_genuineintel.dll", version:"10.0.14393.2516", min_version:"10.0.14393.0", dir:"\system32", bulletin:bulletin, kb:"4091664")
)

{
    replace_kb_item(name:"SMB/Missing"+bulletin, value:TRUE);
    hotfix_security_note();
    exit(0);
}
else
{
  audit(AUDIT_HOST_NOT, "affected");
}
