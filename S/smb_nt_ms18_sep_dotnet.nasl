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
  script_id(117431);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id("CVE-2018-8421");
  script_bugtraq_id(105222);
  script_xref(name:"MSKB", value:"4457035");
  script_xref(name:"MSKB", value:"4457038");
  script_xref(name:"MSKB", value:"4457033");
  script_xref(name:"MSKB", value:"4457142");
  script_xref(name:"MSKB", value:"4457030");
  script_xref(name:"MSKB", value:"4457025");
  script_xref(name:"MSKB", value:"4457027");
  script_xref(name:"MSKB", value:"4457026");
  script_xref(name:"MSKB", value:"4457043");
  script_xref(name:"MSKB", value:"4457028");
  script_xref(name:"MSKB", value:"4457128");
  script_xref(name:"MSKB", value:"4457045");
  script_xref(name:"MSKB", value:"4457044");
  script_xref(name:"MSKB", value:"4457132");
  script_xref(name:"MSKB", value:"4457131");
  script_xref(name:"MSKB", value:"4457036");
  script_xref(name:"MSKB", value:"4457037");
  script_xref(name:"MSKB", value:"4457034");
  script_xref(name:"MSKB", value:"4457053");
  script_xref(name:"MSKB", value:"4457054");
  script_xref(name:"MSKB", value:"4457055");
  script_xref(name:"MSKB", value:"4457056");
  script_xref(name:"MSKB", value:"4457138");
  script_xref(name:"MSKB", value:"4457029");
  script_xref(name:"MSKB", value:"4457042");
  script_xref(name:"MSFT", value:"MS18-4457035");
  script_xref(name:"MSFT", value:"MS18-4457038");
  script_xref(name:"MSFT", value:"MS18-4457033");
  script_xref(name:"MSFT", value:"MS18-4457142");
  script_xref(name:"MSFT", value:"MS18-4457030");
  script_xref(name:"MSFT", value:"MS18-4457025");
  script_xref(name:"MSFT", value:"MS18-4457027");
  script_xref(name:"MSFT", value:"MS18-4457026");
  script_xref(name:"MSFT", value:"MS18-4457043");
  script_xref(name:"MSFT", value:"MS18-4457028");
  script_xref(name:"MSFT", value:"MS18-4457128");
  script_xref(name:"MSFT", value:"MS18-4457045");
  script_xref(name:"MSFT", value:"MS18-4457044");
  script_xref(name:"MSFT", value:"MS18-4457132");
  script_xref(name:"MSFT", value:"MS18-4457131");
  script_xref(name:"MSFT", value:"MS18-4457036");
  script_xref(name:"MSFT", value:"MS18-4457037");
  script_xref(name:"MSFT", value:"MS18-4457034");
  script_xref(name:"MSFT", value:"MS18-4457053");
  script_xref(name:"MSFT", value:"MS18-4457054");
  script_xref(name:"MSFT", value:"MS18-4457055");
  script_xref(name:"MSFT", value:"MS18-4457056");
  script_xref(name:"MSFT", value:"MS18-4457138");
  script_xref(name:"MSFT", value:"MS18-4457029");
  script_xref(name:"MSFT", value:"MS18-4457042");

  script_name(english:"Security Updates for Microsoft .NET Framework (September 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET Framework installation on the remote host is
missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Framework installation on the remote host
is missing a security update. It is, therefore, affected by
the following vulnerability :

  - A remote code execution vulnerability exists when
    Microsoft .NET Framework processes input. An attacker
    who successfully exploited this vulnerability could take
    control of an affected system.  (CVE-2018-8421)");
  # https://support.microsoft.com/en-us/help/4457035/description-of-the-security-and-quality-rollup-for-net-framework-4-6-4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ad8ca318");
  # https://support.microsoft.com/en-us/help/4457038/description-of-the-security-and-quality-rollup-for-net-framework-4-5-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fed37122");
  # https://support.microsoft.com/en-us/help/4457033/description-of-the-security-and-quality-rollup-for-net-framework-4-6-4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?60a8394d");
  # https://support.microsoft.com/en-us/help/4457142/windows-10-update-kb4457142
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?13887e06");
  # https://support.microsoft.com/en-us/help/4457030/description-of-the-security-only-update-for-net-framework-4-5-2-for-wi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db0b04e3");
  # https://support.microsoft.com/en-us/help/4457025/description-of-the-security-only-update-for-net-framework-4-6-4-6-1-4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c1b632e4");
  # https://support.microsoft.com/en-us/help/4457027/description-of-the-security-only-update-for-net-framework-4-6-4-6-1-4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a8e356c6");
  # https://support.microsoft.com/en-us/help/4457026/description-of-the-security-only-update-for-net-framework-4-6-4-6-1-4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba8fc7a2");
  # https://support.microsoft.com/en-us/help/4457043/description-of-the-security-and-quality-rollup-for-net-framework-2-0-s
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f54e1cd2");
  # https://support.microsoft.com/en-us/help/4457028/description-of-the-security-only-update-for-net-framework-4-5-2-for-wi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?49559bb8");
  # https://support.microsoft.com/en-us/help/4457128/windows-10-update-kb4457128
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dee71c23");
  # https://support.microsoft.com/en-us/help/4457045/description-of-the-security-and-quality-rollup-for-net-framework-3-5-f
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ed0492e1");
  # https://support.microsoft.com/en-us/help/4457044/description-of-the-security-and-quality-rollup-for-net-framework-3-5-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d088a5e");
  # https://support.microsoft.com/en-us/help/4457132/windows-10-update-kb4457132
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8e9df1b4");
  # https://support.microsoft.com/en-us/help/4457131/windows-10-update-kb4457131
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db9cdb46");
  # https://support.microsoft.com/en-us/help/4457036/description-of-the-security-and-quality-rollup-for-net-framework-4-5-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?449d58e9");
  # https://support.microsoft.com/en-us/help/4457037/description-of-the-security-and-quality-rollup-for-net-framework-4-5-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3cc1fccb");
  # https://support.microsoft.com/en-us/help/4457034/description-of-the-security-and-quality-rollup-for-net-framework-4-6-4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?df971ee0");
  # https://support.microsoft.com/en-us/help/4457053/description-of-the-security-only-update-for-net-framework-3-5-for-wind
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ea99582");
  # https://support.microsoft.com/en-us/help/4457054/description-of-the-security-only-update-for-net-framework-2-0-sp2-and
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4fb28dc");
  # https://support.microsoft.com/en-us/help/4457055/description-of-the-security-only-update-for-net-framework-3-5-1-for-wi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0e99f7d4");
  # https://support.microsoft.com/en-us/help/4457056/description-of-the-security-only-update-for-net-framework-3-5-for-wind
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3dc3e58e");
  # https://support.microsoft.com/en-us/help/4457138/windows-10-update-kb4457138
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?625cb458");
  # https://support.microsoft.com/en-us/help/4457029/description-of-the-security-only-update-for-net-framework-4-5-2-for-wi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77405e03");
  # https://support.microsoft.com/en-us/help/4457042/description-of-the-security-and-quality-rollup-for-net-framework-3-5-f
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd34e6e6");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft .NET Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8421");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS18-09";
kbs = make_list(
  "4457035",
  "4457038",
  "4457033",
  "4457142",
  "4457030",
  "4457025",
  "4457027",
  "4457026",
  "4457043",
  "4457028",
  "4457128",
  "4457045",
  "4457044",
  "4457132",
  "4457131",
  "4457036",
  "4457037",
  "4457034",
  "4457053",
  "4457054",
  "4457055",
  "4457056",
  "4457138",
  "4457029",
  "4457042"
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
        smb_check_dotnet_rollup(rollup_date:"09_2018", dotnet_ver:version))
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
