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
  script_id(103137);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/30");

  script_cve_id("CVE-2017-8759");
  script_bugtraq_id(100742);
  script_xref(name:"MSFT", value:"MS17-4041086");
  script_xref(name:"MSKB", value:"4041093");
  script_xref(name:"MSFT", value:"MS17-4041093");
  script_xref(name:"MSKB", value:"4041083");
  script_xref(name:"MSFT", value:"MS17-4041083");
  script_xref(name:"MSKB", value:"4041090");
  script_xref(name:"MSFT", value:"MS17-4041090");
  script_xref(name:"MSKB", value:"4041084");
  script_xref(name:"MSFT", value:"MS17-4041084");
  script_xref(name:"MSKB", value:"4041091");
  script_xref(name:"MSFT", value:"MS17-4041091");
  script_xref(name:"MSKB", value:"4041085");
  script_xref(name:"MSFT", value:"MS17-4041085");
  script_xref(name:"MSKB", value:"4041092");
  script_xref(name:"MSFT", value:"MS17-4041092");
  script_xref(name:"MSKB", value:"4038781");
  script_xref(name:"MSFT", value:"MS17-4038781");
  script_xref(name:"MSKB", value:"4038783");
  script_xref(name:"MSFT", value:"MS17-4038783");
  script_xref(name:"MSKB", value:"4038782");
  script_xref(name:"MSFT", value:"MS17-4038782");
  script_xref(name:"MSKB", value:"4038788");
  script_xref(name:"MSFT", value:"MS17-4038788");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Security and Quality Rollup for .NET Framework (Sep 2017)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a software framework installed that is
affected by a security feature bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The .NET Framework installation on the remote host is missing a
security update. It is, therefore, affected by the following
vulnerability:

  - A remote code execution vulnerability exists when Microsoft .NET
    Framework processes untrusted input. An attacker who successfully
    exploited this vulnerability in software using the .NET framework
    could take control of an affected system. An attacker could then
    install programs; view, change, or delete data; or create new
    accounts with full user rights. Users whose accounts are
    configured to have fewer user rights on the system could be less
    impacted than users who operate with administrative user rights.
    (CVE-2017-8759)");
  # https://portal.msrc.microsoft.com/en-us/security-guidance/releasenotedetail/5984735e-f651-e711-80dd-000d3a32fc99
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?39028b0b");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-8759
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a9b7377f");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft .NET Framework
2.0 SP2, 3.5, 3.5.1, 4.5.2, 4.6, 4.6.1, 4.6.2, and 4.7");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8759");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS17-09";
kbs = make_list(
  '4041086', # 2008 SP2 Cumulative Rollup All .Net
  '4041093', # 2008 SP2 Security Only Rollup All .Net
  '4041083', # 7 SP1 / 2008 R2 SP1 Cumulative Rollup All .Net
  '4041090', # 7 SP1 / 2008 R2 SP1 Security Only Rollup All .Net
  '4041084', # Server 2012 Cumulative Rollup All .Net
  '4041091', # Server 2012 Security Only Rollup All .Net
  '4041085', # 8.1 / 2012 R2 Cumulative Rollup All .Net
  '4041092', # 8.1 / 2012 R2 Security Only Rollup All .Net
  '4038781', # 10 RTM Cumulative Rollup All .Net
  '4038783', # 10 1511 Cumulative Rollup All .Net
  '4038782', # 10 1607 / Server 2016 Cumulative Rollup All .Net
  '4038788'  # 10 1703 Cumulative Rollup All .Net
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "Windows 8.1" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);
else if ("Vista" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

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
        smb_check_dotnet_rollup(rollup_date:"09_2017", dotnet_ver:version))
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
  audit(AUDIT_HOST_NOT, "affected");
}
