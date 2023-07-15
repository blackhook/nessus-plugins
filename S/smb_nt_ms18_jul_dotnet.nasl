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
  script_id(110990);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id(
    "CVE-2018-8202",
    "CVE-2018-8260",
    "CVE-2018-8284",
    "CVE-2018-8356"
  );
  script_bugtraq_id(
    104664,
    104665,
    104666,
    104667
  );
  script_xref(name:"MSKB", value:"4338606");
  script_xref(name:"MSKB", value:"4338605");
  script_xref(name:"MSKB", value:"4338604");
  script_xref(name:"MSKB", value:"4338602");
  script_xref(name:"MSKB", value:"4338601");
  script_xref(name:"MSKB", value:"4338600");
  script_xref(name:"MSKB", value:"4338423");
  script_xref(name:"MSKB", value:"4338422");
  script_xref(name:"MSKB", value:"4338421");
  script_xref(name:"MSKB", value:"4338420");
  script_xref(name:"MSKB", value:"4338424");
  script_xref(name:"MSKB", value:"4338819");
  script_xref(name:"MSKB", value:"4338416");
  script_xref(name:"MSKB", value:"4338417");
  script_xref(name:"MSKB", value:"4338415");
  script_xref(name:"MSKB", value:"4338418");
  script_xref(name:"MSKB", value:"4338419");
  script_xref(name:"MSKB", value:"4338610");
  script_xref(name:"MSKB", value:"4338611");
  script_xref(name:"MSKB", value:"4338612");
  script_xref(name:"MSKB", value:"4338613");
  script_xref(name:"MSKB", value:"4338829");
  script_xref(name:"MSKB", value:"4338826");
  script_xref(name:"MSKB", value:"4338825");
  script_xref(name:"MSKB", value:"4338814");
  script_xref(name:"MSFT", value:"MS18-4338606");
  script_xref(name:"MSFT", value:"MS18-4338605");
  script_xref(name:"MSFT", value:"MS18-4338604");
  script_xref(name:"MSFT", value:"MS18-4338602");
  script_xref(name:"MSFT", value:"MS18-4338601");
  script_xref(name:"MSFT", value:"MS18-4338600");
  script_xref(name:"MSFT", value:"MS18-4338423");
  script_xref(name:"MSFT", value:"MS18-4338422");
  script_xref(name:"MSFT", value:"MS18-4338421");
  script_xref(name:"MSFT", value:"MS18-4338420");
  script_xref(name:"MSFT", value:"MS18-4338424");
  script_xref(name:"MSFT", value:"MS18-4338819");
  script_xref(name:"MSFT", value:"MS18-4338416");
  script_xref(name:"MSFT", value:"MS18-4338417");
  script_xref(name:"MSFT", value:"MS18-4338415");
  script_xref(name:"MSFT", value:"MS18-4338418");
  script_xref(name:"MSFT", value:"MS18-4338419");
  script_xref(name:"MSFT", value:"MS18-4338610");
  script_xref(name:"MSFT", value:"MS18-4338611");
  script_xref(name:"MSFT", value:"MS18-4338612");
  script_xref(name:"MSFT", value:"MS18-4338613");
  script_xref(name:"MSFT", value:"MS18-4338829");
  script_xref(name:"MSFT", value:"MS18-4338826");
  script_xref(name:"MSFT", value:"MS18-4338825");
  script_xref(name:"MSFT", value:"MS18-4338814");

  script_name(english:"Security Updates for Microsoft .NET Framework (July 2018) (deprecated)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated due to Microsoft removing downloads
to related KBs.  These were removed due to Access Denied errors which
have been resolved in later cumulative patches.");
  # https://support.microsoft.com/en-us/help/4338606/description-of-the-security-only-update-for-net-framework-4-6-4-6-1-4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6871a6a2");
  # https://support.microsoft.com/en-us/help/4338605/description-of-the-security-only-update-for-net-framework-4-6-4-6-1-4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d62bcc3d");
  # https://support.microsoft.com/en-us/help/4338604/description-of-the-security-only-update-for-net-framework-4-6-4-6-1-4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5af81d47");
  # https://support.microsoft.com/en-us/help/4338602/description-of-the-security-only-update-for-net-framework-4-5-2-for-wi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d75a65af");
  # https://support.microsoft.com/en-us/help/4338601/description-of-the-security-only-update-for-net-framework-4-5-2-for-wi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?44f66a8b");
  # https://support.microsoft.com/en-us/help/4338600/description-of-the-security-only-update-for-net-framework-4-5-2-for-wi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d144042d");
  # https://support.microsoft.com/en-us/help/4338423/description-of-the-security-and-quality-rollup-updates-for-net-framewo
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?df31c224");
  # https://support.microsoft.com/en-us/help/4338422/description-of-the-security-and-quality-rollup-updates-for-net-framewo
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e6a3fb46");
  # https://support.microsoft.com/en-us/help/4338421/description-of-the-security-and-quality-rollup-updates-for-net-framewo
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8908e951");
  # https://support.microsoft.com/en-us/help/4338420/description-of-the-security-and-quality-rollup-updates-for-net-framewo
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1ad1148d");
  # https://support.microsoft.com/en-us/help/4338424/description-of-the-security-and-quality-rollup-for-net-framework-3-5-s
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5f015bf2");
  # https://support.microsoft.com/en-us/help/4338819/windows-10-update-kb4338819
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9bfc0c9");
  # https://support.microsoft.com/en-us/help/4338416/description-of-the-security-and-quality-rollup-updates-for-net-framewo
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce3ef6dc");
  # https://support.microsoft.com/en-us/help/4338417/description-of-the-security-and-quality-rollup-update-for-net-framewor
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?50b55edf");
  # https://support.microsoft.com/en-us/help/4338415/description-of-the-security-and-quality-rollup-updates-for-net-framewo
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8bd31c0d");
  # https://support.microsoft.com/en-us/help/4338418/description-of-the-security-and-quality-rollup-updates-for-net-framewo
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?72e0da05");
  # https://support.microsoft.com/en-us/help/4338419/description-of-the-security-and-quality-rollup-updates-for-net-framewo
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c0096c91");
  # https://support.microsoft.com/en-us/help/4338610/description-of-the-security-only-update-for-net-framework-3-5-for-wind
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1340c27a");
  # https://support.microsoft.com/en-us/help/4338611/description-of-the-security-only-update-for-net-framework-2-0-sp2-and
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17109616");
  # https://support.microsoft.com/en-us/help/4338612/description-of-the-security-only-update-for-net-framework-3-5-1-for-wi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e822fc3");
  # https://support.microsoft.com/en-us/help/4338613/description-of-the-security-only-update-for-net-framework-3-5-for-wind
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?05dcc1e0");
  # https://support.microsoft.com/en-us/help/4338829/windows-10-update-kb4338829
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a0a3fc8a");
  # https://support.microsoft.com/en-us/help/4338826/windows-10-update-kb4338826
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?454614d0");
  # https://support.microsoft.com/en-us/help/4338825/windows-10-update-kb4338825
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3c803961");
  # https://support.microsoft.com/en-us/help/4338814/windows-10-update-kb4338814
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6a189799");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft .NET Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8284");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/10");

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

exit(0,"This plugin has been deprecated, use smb_nt_ms18_aug_dotnet.nasl (plugin 111693) instead");

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = "MS18-07";
kbs = make_list(
  "4338606",
  "4338605",
  "4338604",
  "4338602",
  "4338601",
  "4338600",
  "4338423",
  "4338422",
  "4338421",
  "4338420",
  "4338424",
  "4338819",
  "4338416",
  "4338417",
  "4338415",
  "4338418",
  "4338419",
  "4338610",
  "4338611",
  "4338612",
  "4338613",
  "4338829",
  "4338826",
  "4338825",
  "4338814"
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
        smb_check_dotnet_rollup(rollup_date:"07_2018", dotnet_ver:version))
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
