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
  script_id(109652);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2018-0765", "CVE-2018-1039");
  script_bugtraq_id(104060, 104072);
  script_xref(name:"MSKB", value:"4095512");
  script_xref(name:"MSKB", value:"4095513");
  script_xref(name:"MSKB", value:"4095514");
  script_xref(name:"MSKB", value:"4095515");
  script_xref(name:"MSKB", value:"4095517");
  script_xref(name:"MSKB", value:"4095518");
  script_xref(name:"MSKB", value:"4095519");
  script_xref(name:"MSKB", value:"4095872");
  script_xref(name:"MSKB", value:"4095873");
  script_xref(name:"MSKB", value:"4095874");
  script_xref(name:"MSKB", value:"4095875");
  script_xref(name:"MSKB", value:"4095876");
  script_xref(name:"MSKB", value:"4096235");
  script_xref(name:"MSKB", value:"4096236");
  script_xref(name:"MSKB", value:"4096237");
  script_xref(name:"MSKB", value:"4096416");
  script_xref(name:"MSKB", value:"4096417");
  script_xref(name:"MSKB", value:"4096418");
  script_xref(name:"MSKB", value:"4096494");
  script_xref(name:"MSKB", value:"4096495");
  script_xref(name:"MSKB", value:"4103716");
  script_xref(name:"MSKB", value:"4103721");
  script_xref(name:"MSKB", value:"4103723");
  script_xref(name:"MSKB", value:"4103727");
  script_xref(name:"MSKB", value:"4103731");
  script_xref(name:"MSFT", value:"MS18-4095512");
  script_xref(name:"MSFT", value:"MS18-4095513");
  script_xref(name:"MSFT", value:"MS18-4095514");
  script_xref(name:"MSFT", value:"MS18-4095515");
  script_xref(name:"MSFT", value:"MS18-4095517");
  script_xref(name:"MSFT", value:"MS18-4095518");
  script_xref(name:"MSFT", value:"MS18-4095519");
  script_xref(name:"MSFT", value:"MS18-4095872");
  script_xref(name:"MSFT", value:"MS18-4095873");
  script_xref(name:"MSFT", value:"MS18-4095874");
  script_xref(name:"MSFT", value:"MS18-4095875");
  script_xref(name:"MSFT", value:"MS18-4095876");
  script_xref(name:"MSFT", value:"MS18-4096235");
  script_xref(name:"MSFT", value:"MS18-4096236");
  script_xref(name:"MSFT", value:"MS18-4096237");
  script_xref(name:"MSFT", value:"MS18-4096416");
  script_xref(name:"MSFT", value:"MS18-4096417");
  script_xref(name:"MSFT", value:"MS18-4096418");
  script_xref(name:"MSFT", value:"MS18-4096494");
  script_xref(name:"MSFT", value:"MS18-4096495");
  script_xref(name:"MSFT", value:"MS18-4103716");
  script_xref(name:"MSFT", value:"MS18-4103721");
  script_xref(name:"MSFT", value:"MS18-4103723");
  script_xref(name:"MSFT", value:"MS18-4103727");
  script_xref(name:"MSFT", value:"MS18-4103731");

  script_name(english:"Security Updates for Microsoft .NET Framework (May 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET Framework installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Framework installation on the remote host
is missing security updates. It is, therefore, affected by
multiple vulnerabilities :

  - A security feature bypass vulnerability exists in .Net
    Framework which could allow an attacker to bypass Device
    Guard. An attacker who successfully exploited this
    vulnerability could circumvent a User Mode Code
    Integrity (UMCI) policy on the machine.  (CVE-2018-1039)

  - A denial of service vulnerability exists when .NET and
    .NET Core improperly process XML documents. An attacker
    who successfully exploited this vulnerability could
    cause a denial of service against a .NET application. A
    remote unauthenticated attacker could exploit this
    vulnerability by issuing specially crafted requests to a
    .NET (or .NET core) application. The update addresses
    the vulnerability by correcting how .NET and .NET Core
    applications handle XML document processing.
    (CVE-2018-0765)");
  # https://support.microsoft.com/en-us/help/4096237/description-of-the-security-only-update-for-net-framework-4-6-4-6-1-4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c09ca2b");
  # https://support.microsoft.com/en-us/help/4096236/description-of-the-security-only-update-for-net-framework-4-6-4-6-1-4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7a7d72d3");
  # https://support.microsoft.com/en-us/help/4095872/description-of-the-security-and-quality-rollup-for-net-framework-3-5-f
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3fe33cd0");
  # https://support.microsoft.com/en-us/help/4095873/description-of-the-security-and-quality-rollup-for-net-framework-2-0-s
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3396f0cc");
  # https://support.microsoft.com/en-us/help/4095874/description-of-the-security-and-quality-rollup-for-net-framework-3-5-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0dcf45ad");
  # https://support.microsoft.com/en-us/help/4095875/description-of-the-security-and-quality-rollup-for-net-framework-3-5-f
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d006f874");
  # https://support.microsoft.com/en-us/help/4095876/description-of-the-security-and-quality-rollup-for-net-framework-4-5-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01808ffe");
  # https://support.microsoft.com/en-us/help/4096495/description-of-the-security-and-quality-rollup-for-net-framework-4-5-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c0b4dd6d");
  # https://support.microsoft.com/en-us/help/4096494/description-of-the-security-and-quality-rollup-for-net-framework-4-5-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5483f9b8");
  # https://support.microsoft.com/en-us/help/4103731/windows-10-update-kb4103731
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e6fc001a");
  # https://support.microsoft.com/en-us/help/4103716/windows-10-update-kb4103716
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb504ab5");
  # https://support.microsoft.com/en-us/help/4096418/description-of-the-security-and-quality-rollup-for-net-framework-4-6-4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8a34215b");
  # https://support.microsoft.com/en-us/help/4095519/description-of-the-security-only-update-for-net-framework-4-5-2-for-wi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c30e2b96");
  # https://support.microsoft.com/en-us/help/4095518/description-of-the-security-only-update-for-net-framework-4-5-2-for-wi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6c6f6f2b");
  # https://support.microsoft.com/en-us/help/4095517/description-of-the-security-only-update-for-net-framework-4-5-2-for-wi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?78d71558");
  # https://support.microsoft.com/en-us/help/4095513/description-of-the-security-only-update-for-net-framework-2-0-sp2-and
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fafc93a");
  # https://support.microsoft.com/en-us/help/4095515/description-of-the-security-only-update-for-net-framework-3-5-sp1-for
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c993d489");
  # https://support.microsoft.com/en-us/help/4095514/description-of-the-security-only-update-for-net-framework-3-5-1-for-wi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a80d2f6a");
  # https://support.microsoft.com/en-us/help/4096417/description-of-the-security-and-quality-rollup-for-net-framework-4-6-4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d71b2a16");
  # https://support.microsoft.com/en-us/help/4095512/description-of-the-security-only-update-for-net-framework-3-5-sp1-for
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cfc3021f");
  # https://support.microsoft.com/en-us/help/4096416/description-of-the-security-and-quality-rollup-for-net-framework-4-6-4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f6e88e34");
  # https://support.microsoft.com/en-us/help/4096235/description-of-the-security-only-update-for-net-framework-4-6-4-6-1-4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e553999f");
  # https://support.microsoft.com/en-us/help/4103721/windows-10-update-kb4103721
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d0d5cd2");
  # https://support.microsoft.com/en-us/help/4103723/windows-10-update-kb4103723
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aca51532");
  # https://support.microsoft.com/en-us/help/4103727/windows-10-update-kb4103727
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?41c43cb2");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft .NET Framework.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1039");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/09");

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

bulletin = "MS18-05";
kbs = make_list(
  '4095512',
  '4095513',
  '4095514',
  '4095515',
  '4095517',
  '4095518',
  '4095519',
  '4095872',
  '4095873',
  '4095874',
  '4095875',
  '4095876',
  '4096235',
  '4096236',
  '4096237',
  '4096416',
  '4096417',
  '4096418',
  '4096494',
  '4096495',
  '4103716',
  '4103721',
  '4103723',
  '4103727',
  '4103731'
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
        smb_check_dotnet_rollup(rollup_date:"05_2018", dotnet_ver:version))
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
