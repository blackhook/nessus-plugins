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
  script_id(119612);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id("CVE-2018-8517", "CVE-2018-8540");
  script_xref(name:"MSKB", value:"4470637");
  script_xref(name:"MSKB", value:"4470493");
  script_xref(name:"MSKB", value:"4470492");
  script_xref(name:"MSKB", value:"4470491");
  script_xref(name:"MSKB", value:"4470630");
  script_xref(name:"MSKB", value:"4470639");
  script_xref(name:"MSKB", value:"4470498");
  script_xref(name:"MSKB", value:"4471323");
  script_xref(name:"MSKB", value:"4471321");
  script_xref(name:"MSKB", value:"4471327");
  script_xref(name:"MSKB", value:"4471324");
  script_xref(name:"MSKB", value:"4471329");
  script_xref(name:"MSKB", value:"4470640");
  script_xref(name:"MSKB", value:"4470641");
  script_xref(name:"MSKB", value:"4470500");
  script_xref(name:"MSKB", value:"4470502");
  script_xref(name:"MSKB", value:"4470622");
  script_xref(name:"MSKB", value:"4470623");
  script_xref(name:"MSKB", value:"4470602");
  script_xref(name:"MSKB", value:"4470629");
  script_xref(name:"MSKB", value:"4470600");
  script_xref(name:"MSKB", value:"4470601");
  script_xref(name:"MSKB", value:"4470499");
  script_xref(name:"MSKB", value:"4470638");
  script_xref(name:"MSFT", value:"MS18-4470637");
  script_xref(name:"MSFT", value:"MS18-4470493");
  script_xref(name:"MSFT", value:"MS18-4470492");
  script_xref(name:"MSFT", value:"MS18-4470491");
  script_xref(name:"MSFT", value:"MS18-4470630");
  script_xref(name:"MSFT", value:"MS18-4470639");
  script_xref(name:"MSFT", value:"MS18-4470498");
  script_xref(name:"MSFT", value:"MS18-4471323");
  script_xref(name:"MSFT", value:"MS18-4471321");
  script_xref(name:"MSFT", value:"MS18-4471327");
  script_xref(name:"MSFT", value:"MS18-4471324");
  script_xref(name:"MSFT", value:"MS18-4471329");
  script_xref(name:"MSFT", value:"MS18-4470640");
  script_xref(name:"MSFT", value:"MS18-4470641");
  script_xref(name:"MSFT", value:"MS18-4470500");
  script_xref(name:"MSFT", value:"MS18-4470502");
  script_xref(name:"MSFT", value:"MS18-4470622");
  script_xref(name:"MSFT", value:"MS18-4470623");
  script_xref(name:"MSFT", value:"MS18-4470602");
  script_xref(name:"MSFT", value:"MS18-4470629");
  script_xref(name:"MSFT", value:"MS18-4470600");
  script_xref(name:"MSFT", value:"MS18-4470601");
  script_xref(name:"MSFT", value:"MS18-4470499");
  script_xref(name:"MSFT", value:"MS18-4470638");

  script_name(english:"Security Updates for Microsoft .NET Framework (December 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET Framework installation on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Framework installation on the remote host
is missing security updates. It is, therefore, affected by
multiple vulnerabilities :

  - A remote code execution vulnerability exists when the
    Microsoft .NET Framework fails to validate input
    properly. An attacker who successfully exploited this
    vulnerability could take control of an affected system.
    An attacker could then install programs; view, change,
    or delete data; or create new accounts with full user
    rights. Users whose accounts are configured to have
    fewer user rights on the system could be less impacted
    than users who operate with administrative user rights.
    (CVE-2018-8540)

  - A denial of service vulnerability exists when .NET
    Framework improperly handles special web requests. An
    attacker who successfully exploited this vulnerability
    could cause a denial of service against an .NET
    Framework web application. The vulnerability can be
    exploited remotely, without authentication. A remote
    unauthenticated attacker could exploit this
    vulnerability by issuing specially crafted requests to
    the .NET Framework application. The update addresses the
    vulnerability by correcting how the .NET Framework web
    application handles web requests. (CVE-2018-8517)");
  # https://support.microsoft.com/en-us/help/4470637/description-of-security-and-quality-rollup-for-net-framework-4-5-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6380ea56");
  # https://support.microsoft.com/en-us/help/4470493/description-of-the-security-only-update-for-net-framework-4-5-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc71683a");
  # https://support.microsoft.com/en-us/help/4470492/description-of-security-only-update-for-net-framework-4-5-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb77a3a9");
  # https://support.microsoft.com/en-us/help/4470491/description-of-security-only-update-for-net-framework-4-5-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?387e7480");
  # https://support.microsoft.com/en-us/help/4470630/description-security-and-quality-rollup-for-net-framework-3-5-to-4-7-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f183eaa6");
  # https://support.microsoft.com/en-us/help/4470639/description-security-and-quality-rollup-for-net-framework-4-6-to-4-7-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1b234efa");
  # https://support.microsoft.com/en-us/help/4470498/description-of-security-only-update-for-net-framework-4-6-to-4-7-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5ab75ee");
  # https://support.microsoft.com/en-us/help/4471323/windows-10-update-kb4471323
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b3e08e7");
  # https://support.microsoft.com/en-us/help/4471321/windows-10-update-kb4471321
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?417b4781");
  # https://support.microsoft.com/en-us/help/4471327/windows-10-update-kb4471327
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8b54dbf3");
  # https://support.microsoft.com/en-us/help/4471324/windows-10-update-kb4471324
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7a2a924f");
  # https://support.microsoft.com/en-us/help/4471329/windows-10-update-kb4471329
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?24e3688b");
  # https://support.microsoft.com/en-us/help/4470640/description-of-security-and-quality-rollup-for-net-framework-4-6-4-7-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?379ac7eb");
  # https://support.microsoft.com/en-us/help/4470641/description-of-security-and-quality-rollup-for-net-framework-3-5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b7367a8b");
  # https://support.microsoft.com/en-us/help/4470500/description-of-security-only-update-for-net-framework-4-6-to-4-7-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e5e76310");
  # https://support.microsoft.com/en-us/help/4470502/december-11-2018-kb4470502
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?97b022e8");
  # https://support.microsoft.com/en-us/help/4470622/description-security-and-quality-rollup-for-net-framework-4-5-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?54221753");
  # https://support.microsoft.com/en-us/help/4470623/description-of-security-and-quality-rollup-for-net-framework-4-5-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0dcb6757");
  # https://support.microsoft.com/en-us/help/4470602/description-of-security-only-update-for-net-framework-3-5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1f448e1");
  # https://support.microsoft.com/en-us/help/4470629/description-of-security-and-quality-rollup-for-net-framework-3-5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb7cea66");
  # https://support.microsoft.com/en-us/help/4470600/description-of-security-only-update-for-net-framework-3-5-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?71423e93");
  # https://support.microsoft.com/en-us/help/4470601/description-of-security-only-update-for-net-framework-3-5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc5d46b3");
  # https://support.microsoft.com/en-us/help/4470499/description-of-security-only-update-for-net-framework-4-6-to-4-7-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?638e3db2");
  # https://support.microsoft.com/en-us/help/4470638/description-security-and-quality-rollup-for-net-framework-4-6-to-4-7-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6669e114");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft .NET Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8540");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/13");

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

bulletin = "MS18-12";
kbs = make_list(
  "4470637",
  "4470493",
  "4470492",
  "4470491",
  "4470630",
  "4470639",
  "4470498",
  "4471323",
  "4471321",
  "4471327",
  "4471324",
  "4471329",
  "4470640",
  "4470641",
  "4470500",
  "4470502",
  "4470622",
  "4470623",
  "4470602",
  "4470629",
  "4470600",
  "4470601",
  "4470499",
  "4470638"
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
        smb_check_dotnet_rollup(rollup_date:"12_2018", dotnet_ver:version))
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
