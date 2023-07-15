#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(171598);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/16");

  script_cve_id("CVE-2023-21722", "CVE-2023-21808");
  script_xref(name:"MSKB", value:"5022497");
  script_xref(name:"MSKB", value:"5022498");
  script_xref(name:"MSKB", value:"5022499");
  script_xref(name:"MSKB", value:"5022501");
  script_xref(name:"MSKB", value:"5022502");
  script_xref(name:"MSKB", value:"5022503");
  script_xref(name:"MSKB", value:"5022504");
  script_xref(name:"MSKB", value:"5022505");
  script_xref(name:"MSKB", value:"5022506");
  script_xref(name:"MSKB", value:"5022507");
  script_xref(name:"MSKB", value:"5022508");
  script_xref(name:"MSKB", value:"5022509");
  script_xref(name:"MSKB", value:"5022511");
  script_xref(name:"MSKB", value:"5022512");
  script_xref(name:"MSKB", value:"5022513");
  script_xref(name:"MSKB", value:"5022514");
  script_xref(name:"MSKB", value:"5022515");
  script_xref(name:"MSKB", value:"5022516");
  script_xref(name:"MSKB", value:"5022520");
  script_xref(name:"MSKB", value:"5022521");
  script_xref(name:"MSKB", value:"5022522");
  script_xref(name:"MSKB", value:"5022523");
  script_xref(name:"MSKB", value:"5022524");
  script_xref(name:"MSKB", value:"5022525");
  script_xref(name:"MSKB", value:"5022526");
  script_xref(name:"MSKB", value:"5022529");
  script_xref(name:"MSKB", value:"5022530");
  script_xref(name:"MSKB", value:"5022531");
  script_xref(name:"MSKB", value:"5022574");
  script_xref(name:"MSKB", value:"5022575");
  script_xref(name:"MSFT", value:"MS23-5022497");
  script_xref(name:"MSFT", value:"MS23-5022498");
  script_xref(name:"MSFT", value:"MS23-5022499");
  script_xref(name:"MSFT", value:"MS23-5022501");
  script_xref(name:"MSFT", value:"MS23-5022502");
  script_xref(name:"MSFT", value:"MS23-5022503");
  script_xref(name:"MSFT", value:"MS23-5022504");
  script_xref(name:"MSFT", value:"MS23-5022505");
  script_xref(name:"MSFT", value:"MS23-5022506");
  script_xref(name:"MSFT", value:"MS23-5022507");
  script_xref(name:"MSFT", value:"MS23-5022508");
  script_xref(name:"MSFT", value:"MS23-5022509");
  script_xref(name:"MSFT", value:"MS23-5022511");
  script_xref(name:"MSFT", value:"MS23-5022512");
  script_xref(name:"MSFT", value:"MS23-5022513");
  script_xref(name:"MSFT", value:"MS23-5022514");
  script_xref(name:"MSFT", value:"MS23-5022515");
  script_xref(name:"MSFT", value:"MS23-5022516");
  script_xref(name:"MSFT", value:"MS23-5022520");
  script_xref(name:"MSFT", value:"MS23-5022521");
  script_xref(name:"MSFT", value:"MS23-5022522");
  script_xref(name:"MSFT", value:"MS23-5022523");
  script_xref(name:"MSFT", value:"MS23-5022524");
  script_xref(name:"MSFT", value:"MS23-5022525");
  script_xref(name:"MSFT", value:"MS23-5022526");
  script_xref(name:"MSFT", value:"MS23-5022529");
  script_xref(name:"MSFT", value:"MS23-5022530");
  script_xref(name:"MSFT", value:"MS23-5022531");
  script_xref(name:"MSFT", value:"MS23-5022574");
  script_xref(name:"MSFT", value:"MS23-5022575");
  script_xref(name:"IAVA", value:"2023-A-0087-S");

  script_name(english:"Security Updates for Microsoft .NET Framework (February 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update. It is, therefore, affected
by multiple vulnerabilities, as follows:

  - A denial of service (DoS) vulnerability. (CVE-2023-21722)

  - A remote code execution vulnerability. (CVE-2023-21808)");
  # https://devblogs.microsoft.com/dotnet/dotnet-framework-february-2023-security-and-quality-rollup-updates/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5bd7d30c");
  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2023-21808
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42dae88f");
  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2023-21722
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db0b1765");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5022497");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5022498");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5022499");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5022501");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5022502");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5022503");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5022504");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5022505");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5022506");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5022507");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5022508");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5022509");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5022511");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5022512");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5022513");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5022514");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5022515");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5022516");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5022520");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5022521");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5022522");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5022523");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5022524");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5022525");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5022526");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5022529");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5022530");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5022531");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5022574");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5022575");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft .NET Framework.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21808");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_dotnet_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "microsoft_net_framework_installed.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('install_func.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

var bulletin = 'MS23-02';
var kbs = make_list(
  "5022497",
  "5022498",
  "5022499",
  "5022501",
  "5022502",
  "5022503",
  "5022504",
  "5022505",
  "5022506",
  "5022507",
  "5022508",
  "5022509",
  "5022511",
  "5022512",
  "5022513",
  "5022514",
  "5022515",
  "5022516",
  "5022520",
  "5022521",
  "5022522",
  "5022523",
  "5022524",
  "5022525",
  "5022526",
  "5022529",
  "5022530",
  "5022531",
  "5022574",
  "5022575"
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(vista:'2' , win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

var share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

var app = 'Microsoft .NET Framework';
get_install_count(app_name:app, exit_if_zero:TRUE);
var installs = get_combined_installs(app_name:app);

var install, version;
var vuln = 0;

if (installs[0] == 0)
{
  foreach install (installs[1])
  {
    version = install['version'];
    if( version != UNKNOWN_VER &&
        smb_check_dotnet_rollup(rollup_date:'02_2023', dotnet_ver:version))
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
  audit(AUDIT_HOST_NOT, 'affected');
}
