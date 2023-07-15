#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(122234);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/28");

  script_cve_id("CVE-2019-0613", "CVE-2019-0657", "CVE-2019-0663");
  script_bugtraq_id(106872, 106890);
  script_xref(name:"MSKB", value:"4483482");
  script_xref(name:"MSKB", value:"4483483");
  script_xref(name:"MSKB", value:"4483481");
  script_xref(name:"MSKB", value:"4483484");
  script_xref(name:"MSKB", value:"4487020");
  script_xref(name:"MSKB", value:"4487026");
  script_xref(name:"MSKB", value:"4483449");
  script_xref(name:"MSKB", value:"4483468");
  script_xref(name:"MSKB", value:"4483469");
  script_xref(name:"MSKB", value:"4486996");
  script_xref(name:"MSKB", value:"4483474");
  script_xref(name:"MSKB", value:"4487018");
  script_xref(name:"MSKB", value:"4483473");
  script_xref(name:"MSKB", value:"4487017");
  script_xref(name:"MSKB", value:"4483454");
  script_xref(name:"MSKB", value:"4483451");
  script_xref(name:"MSKB", value:"4483450");
  script_xref(name:"MSKB", value:"4483453");
  script_xref(name:"MSKB", value:"4483452");
  script_xref(name:"MSKB", value:"4483455");
  script_xref(name:"MSKB", value:"4483472");
  script_xref(name:"MSKB", value:"4483457");
  script_xref(name:"MSKB", value:"4483456");
  script_xref(name:"MSKB", value:"4483459");
  script_xref(name:"MSKB", value:"4483458");
  script_xref(name:"MSKB", value:"4483470");
  script_xref(name:"MSFT", value:"MS19-4483482");
  script_xref(name:"MSFT", value:"MS19-4483483");
  script_xref(name:"MSFT", value:"MS19-4483481");
  script_xref(name:"MSFT", value:"MS19-4483484");
  script_xref(name:"MSFT", value:"MS19-4487020");
  script_xref(name:"MSFT", value:"MS19-4487026");
  script_xref(name:"MSFT", value:"MS19-4483449");
  script_xref(name:"MSFT", value:"MS19-4483468");
  script_xref(name:"MSFT", value:"MS19-4483469");
  script_xref(name:"MSFT", value:"MS19-4486996");
  script_xref(name:"MSFT", value:"MS19-4483474");
  script_xref(name:"MSFT", value:"MS19-4487018");
  script_xref(name:"MSFT", value:"MS19-4483473");
  script_xref(name:"MSFT", value:"MS19-4487017");
  script_xref(name:"MSFT", value:"MS19-4483454");
  script_xref(name:"MSFT", value:"MS19-4483451");
  script_xref(name:"MSFT", value:"MS19-4483450");
  script_xref(name:"MSFT", value:"MS19-4483453");
  script_xref(name:"MSFT", value:"MS19-4483452");
  script_xref(name:"MSFT", value:"MS19-4483455");
  script_xref(name:"MSFT", value:"MS19-4483472");
  script_xref(name:"MSFT", value:"MS19-4483457");
  script_xref(name:"MSFT", value:"MS19-4483456");
  script_xref(name:"MSFT", value:"MS19-4483459");
  script_xref(name:"MSFT", value:"MS19-4483458");
  script_xref(name:"MSFT", value:"MS19-4483470");

  script_name(english:"Security Updates for Microsoft .NET Framework (February 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET Framework installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Framework installation on the remote host
is missing security updates. It is, therefore, affected by
multiple vulnerabilities :

  - A remote code execution vulnerability exists in .NET
    Framework and Visual Studio software when the software
    fails to check the source markup of a file. An attacker
    who successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2019-0613)

  - A vulnerability exists in certain .Net Framework API's
    and Visual Studio in the way they parse URL's. An
    attacker who successfully exploited this vulnerability
    could use it to bypass security logic intended to ensure
    that a user-provided URL belonged to a specific hostname
    or a subdomain of that hostname. This could be used to
    cause privileged communication to be made to an
    untrusted service as if it was a trusted service.
    (CVE-2019-0657)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly initializes objects in memory.
    To exploit this vulnerability, an authenticated attacker
    could run a specially crafted application. An attacker who
    successfully exploited this vulnerability could obtain
    information to further compromise the user's system.
    (CVE-2019-0663)");
  # https://support.microsoft.com/en-us/help/4483482/description-of-the-security-only-update-for-net-framework-2-0-and-3-0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a115f2fd");
  # https://support.microsoft.com/en-us/help/4483483/description-of-the-security-only-update-for-net-framework-3-5-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30834b20");
  # https://support.microsoft.com/en-us/help/4483481/description-of-the-security-only-update-for-net-framework-3-5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?019cea8f");
  # https://support.microsoft.com/en-us/help/4483484/description-of-the-security-only-update-for-net-framework-3-5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?36c1f0d4");
  # https://support.microsoft.com/en-us/help/4487020/windows-10-update-kb4487020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c56bb182");
  # https://support.microsoft.com/en-us/help/4487026/windows-10-update-kb4487026
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?647a783e");
  # https://support.microsoft.com/en-us/help/4483449/description-of-security-and-quality-rollup-net-framework-4-6-to-4-7-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d8094ee");
  # https://support.microsoft.com/en-us/help/4483468/description-of-the-security-only-update-for-net-framework-4-6-to-4-7-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?98ffee64");
  # https://support.microsoft.com/en-us/help/4483469/description-of-the-security-only-update-for-net-framework-4-6-to-4-7-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7bef4183");
  # https://support.microsoft.com/en-us/help/4486996/windows-10-update-kb4486996
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e794af1");
  # https://support.microsoft.com/en-us/help/4483474/description-of-the-security-only-update-for-net-framework-4-5-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4173d6f6");
  # https://support.microsoft.com/en-us/help/4487018/windows-10-update-kb4487018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4d94fb34");
  # https://support.microsoft.com/en-us/help/4483473/description-of-the-security-only-update-for-net-framework-4-5-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?21ccafb3");
  # https://support.microsoft.com/en-us/help/4487017/windows-10-update-kb4487017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f84e87c3");
  # https://support.microsoft.com/en-us/help/4483454/description-of-the-security-and-quality-rollup-for-net-framework-4-5-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc58c2d9");
  # https://support.microsoft.com/en-us/help/4483451/description-security-and-quality-rollup-for-net-framework-4-6-to-4-7-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1aec536e");
  # https://support.microsoft.com/en-us/help/4483450/description-of-security-and-quality-rollup-net-framework-4-6-to-4-7-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0db4b115");
  # https://support.microsoft.com/en-us/help/4483453/description-of-the-security-and-quality-rollup-for-net-framework-4-5-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?97d57080");
  # https://support.microsoft.com/en-us/help/4483452/february-12-2019-kb4483452
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?258ca8fb");
  # https://support.microsoft.com/en-us/help/4483455/description-of-the-security-and-quality-rollup-for-net-framework-4-5-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8553f70f");
  # https://support.microsoft.com/en-us/help/4483472/description-of-the-security-only-update-for-net-framework-4-5-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e5ba9677");
  # https://support.microsoft.com/en-us/help/4483457/description-of-the-security-and-quality-rollup-for-net-framework-2-0-a
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f2bda833");
  # https://support.microsoft.com/en-us/help/4483456/description-of-the-security-and-quality-rollup-for-net-framework-3-5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?25ef9544");
  # https://support.microsoft.com/en-us/help/4483459/description-of-the-security-and-quality-rollup-for-net-framework-3-5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba6e7bcf");
  # https://support.microsoft.com/en-us/help/4483458/description-of-the-security-and-quality-rollup-for-net-framework-3-5-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d44bccd0");
  # https://support.microsoft.com/en-us/help/4483470/description-of-the-security-only-update-for-net-framework-4-6-to-4-7-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?65585675");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft .NET Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0613");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS19-02";
kbs = make_list(
  "4483449",
  "4483450",
  "4483451",
  "4483452",
  "4483453",
  "4483454",
  "4483455",
  "4483456",
  "4483457",
  "4483458",
  "4483459",
  "4483468",
  "4483469",
  "4483470",
  "4483472",
  "4483473",
  "4483474",
  "4483481",
  "4483482",
  "4483483",
  "4483484",
  "4486996",
  "4487017",
  "4487018",
  "4487020",
  "4487026"
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
        smb_check_dotnet_rollup(rollup_date:"02_2019", dotnet_ver:version))
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
