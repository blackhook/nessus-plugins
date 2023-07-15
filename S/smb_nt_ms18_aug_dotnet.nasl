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
  script_id(111693);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-8360");
  script_bugtraq_id(104986);
  script_xref(name:"MSKB", value:"4343887");
  script_xref(name:"MSKB", value:"4343885");
  script_xref(name:"MSKB", value:"4343909");
  script_xref(name:"MSKB", value:"4344147");
  script_xref(name:"MSKB", value:"4344146");
  script_xref(name:"MSKB", value:"4344145");
  script_xref(name:"MSKB", value:"4344144");
  script_xref(name:"MSKB", value:"4344165");
  script_xref(name:"MSKB", value:"4344167");
  script_xref(name:"MSKB", value:"4344166");
  script_xref(name:"MSKB", value:"4344149");
  script_xref(name:"MSKB", value:"4344148");
  script_xref(name:"MSKB", value:"4344152");
  script_xref(name:"MSKB", value:"4343897");
  script_xref(name:"MSKB", value:"4343892");
  script_xref(name:"MSKB", value:"4344150");
  script_xref(name:"MSKB", value:"4344151");
  script_xref(name:"MSKB", value:"4344178");
  script_xref(name:"MSKB", value:"4344153");
  script_xref(name:"MSKB", value:"4344176");
  script_xref(name:"MSKB", value:"4344177");
  script_xref(name:"MSKB", value:"4344175");
  script_xref(name:"MSKB", value:"4344172");
  script_xref(name:"MSKB", value:"4344173");
  script_xref(name:"MSKB", value:"4344171");
  script_xref(name:"MSFT", value:"MS18-4343887");
  script_xref(name:"MSFT", value:"MS18-4343885");
  script_xref(name:"MSFT", value:"MS18-4343909");
  script_xref(name:"MSFT", value:"MS18-4344147");
  script_xref(name:"MSFT", value:"MS18-4344146");
  script_xref(name:"MSFT", value:"MS18-4344145");
  script_xref(name:"MSFT", value:"MS18-4344144");
  script_xref(name:"MSFT", value:"MS18-4344165");
  script_xref(name:"MSFT", value:"MS18-4344167");
  script_xref(name:"MSFT", value:"MS18-4344166");
  script_xref(name:"MSFT", value:"MS18-4344149");
  script_xref(name:"MSFT", value:"MS18-4344148");
  script_xref(name:"MSFT", value:"MS18-4344152");
  script_xref(name:"MSFT", value:"MS18-4343897");
  script_xref(name:"MSFT", value:"MS18-4343892");
  script_xref(name:"MSFT", value:"MS18-4344150");
  script_xref(name:"MSFT", value:"MS18-4344151");
  script_xref(name:"MSFT", value:"MS18-4344178");
  script_xref(name:"MSFT", value:"MS18-4344153");
  script_xref(name:"MSFT", value:"MS18-4344176");
  script_xref(name:"MSFT", value:"MS18-4344177");
  script_xref(name:"MSFT", value:"MS18-4344175");
  script_xref(name:"MSFT", value:"MS18-4344172");
  script_xref(name:"MSFT", value:"MS18-4344173");
  script_xref(name:"MSFT", value:"MS18-4344171");

  script_name(english:"Security Updates for Microsoft .NET Framework (August 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Framework installation on the remote host
is missing a security update. It is, therefore, affected by
the following vulnerability :

  - An information disclosure vulnerability exists in
    Microsoft .NET Framework that could allow an attacker to
    access information in multi-tenant environments. The
    vulnerability is caused when .NET Framework is used in
    high-load/high-density network connections where content
    from one stream can blend into another stream.
    (CVE-2018-8360)");
  # https://support.microsoft.com/en-us/help/4343887/windows-10-update-kb4343887
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?93e63484");
  # https://support.microsoft.com/en-us/help/4343885/windows-10-update-kb4343885
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2be0b30b");
  # https://support.microsoft.com/en-us/help/4343909/windows-10-update-kb4343909
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3356f605");
  # https://support.microsoft.com/en-us/help/4344147/description-of-the-security-and-quality-rollup-for-net-framework-4-5-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?09b4cda4");
  # https://support.microsoft.com/en-us/help/4344146/description-of-the-security-and-quality-rollup-for-net-framework-4-6-4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d44cd3a");
  # https://support.microsoft.com/en-us/help/4344145/description-of-the-security-and-quality-rollup-for-net-framework-4-6-4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?28c48173");
  # https://support.microsoft.com/en-us/help/4344144/description-of-the-security-and-quality-rollup-for-net-framework-4-6-4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cd89d90f");
  # https://support.microsoft.com/en-us/help/4344165/description-of-the-security-only-update-for-net-framework-4-6-4-6-1-4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2837f4a2");
  # https://support.microsoft.com/en-us/help/4344167/description-of-the-security-only-update-for-net-framework-4-6-4-6-1-4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bf699f3a");
  # https://support.microsoft.com/en-us/help/4344166/description-of-the-security-only-update-for-net-framework-4-6-4-6-1-4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?124e7bc7");
  # https://support.microsoft.com/en-us/help/4344149/description-of-the-security-and-quality-rollup-for-net-framework-4-5-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cb3801fe");
  # https://support.microsoft.com/en-us/help/4344148/description-of-the-security-and-quality-rollup-for-net-framework-4-5-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ab9852e");
  # https://support.microsoft.com/en-us/help/4344152/description-of-the-security-and-quality-rollup-for-net-framework-3-5-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f052611d");
  # https://support.microsoft.com/en-us/help/4343897/windows-10-update-kb4343897
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?770b7995");
  # https://support.microsoft.com/en-us/help/4343892/windows-10-update-kb4343892
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e04d903e");
  # https://support.microsoft.com/en-us/help/4344150/description-of-the-security-and-quality-rollup-for-net-framework-3-5-f
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e98b4c8a");
  # https://support.microsoft.com/en-us/help/4344151/description-of-the-security-and-quality-rollup-for-net-framework-2-0-s
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d39617b");
  # https://support.microsoft.com/en-us/help/4344178/description-of-the-security-only-update-for-net-framework-3-5-for-wind
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?088c4696");
  # https://support.microsoft.com/en-us/help/4344153/description-of-the-security-and-quality-rollup-for-net-framework-3-5-f
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9775d00a");
  # https://support.microsoft.com/en-us/help/4344176/description-of-the-security-only-update-for-net-framework-2-0-sp2-and
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d0e06c76");
  # https://support.microsoft.com/en-us/help/4344177/description-of-the-security-only-update-for-net-framework-3-5-1-for-wi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?44da5a9a");
  # https://support.microsoft.com/en-us/help/4344175/description-of-the-security-only-update-for-net-framework-3-5-for-wind
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c14a7305");
  # https://support.microsoft.com/en-us/help/4344172/description-of-the-security-only-update-for-net-framework-4-5-2-for-wi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17554e6e");
  # https://support.microsoft.com/en-us/help/4344173/description-of-the-security-only-update-for-net-framework-4-5-2-for-wi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8618865f");
  # https://support.microsoft.com/en-us/help/4344171/description-of-the-security-only-update-for-net-framework-4-5-2-for-wi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd8bc23c");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft .NET Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8360");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/14");

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

bulletin = "MS18-08";
kbs = make_list(
  "4343885",
  "4343887",
  "4343892",
  "4343897",
  "4343909",
  "4344144",
  "4344145",
  "4344146",
  "4344147",
  "4344148",
  "4344149",
  "4344150",
  "4344151",
  "4344152",
  "4344153",
  "4344165",
  "4344166",
  "4344167",
  "4344171",
  "4344172",
  "4344173",
  "4344175",
  "4344176",
  "4344177",
  "4344178"
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

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
        smb_check_dotnet_rollup(rollup_date:"08_2018", dotnet_ver:version))
      vuln++;
  }
}
if(vuln)
{
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, "affected");
}
