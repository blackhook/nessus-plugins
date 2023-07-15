#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174991);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/21");

  script_cve_id("CVE-2022-41099");
  script_xref(name:"MSKB", value:"5025175");
  script_xref(name:"MSFT", value:"MS23-5025175");

  script_name(english:"Windows Recovery Environment BitLocker Bypass (KB5025175)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host may be affected by a security feature bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has not had the post-update scripts described in Microsoft KB5025175 executed. It may,
therefore, be affected by a BitLocker security feature bypass vulnerability if the Windows Recovery Environment (WinRE)
has not been update by an alternative method.

Note that Nessus has not tested for these issues but has instead relied only on the absence of breadcrumbs placed on
the system by the remediation script.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5025175");
  script_set_attribute(attribute:"solution", value:
"Run the update scripts as described in KB5025175");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41099");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersionBuild", "Settings/ParanoidReport");
  script_require_ports(139, 445);

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');

# This script only checks for breadcrumbs left by the Microsoft update script
# provided in this KB. It is possible to update WinRE manually and therefore
# not be affected by the vulnerability but in a way this script cannot detect.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

get_kb_item_or_exit('SMB/Registry/Enumerated');
var osbuild = get_kb_item_or_exit("SMB/WindowsVersionBuild");
var productname = get_kb_item_or_exit("SMB/ProductName");

# The script we are checking for only works on certain versions of Windows 10 and 11
# so check to make sure we're running on those before checking if the script ran
# Note that Windows 10 has build numbers 19041 -> 19045 potentially vulnerable by
# the file the script checks is 19041 for all of these so we need to be a bit more
# liberal in handling osbuild numbers than the script.
if ((osbuild != 10240 && osbuild != 14393 && osbuild != 17763 && osbuild != 19041 &&
    osbuild != 19042 && osbuild != 19043 && osbuild != 19044 && osbuild != 19045 &&
    osbuild != 22000 && osbuild != 22621) || ('Windows Server' >< productname))
  audit(AUDIT_HOST_NOT, 'an affected version of Windows');

var share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share))
  audit(AUDIT_SHARE_FAIL, share);


registry_init();
var handle = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
var key = "SOFTWARE\Microsoft\PushButtonReset\WinREPathScriptSucceed";
var item = get_registry_value(handle:handle, item:key);
RegCloseKey(handle:handle);

if (item == 1)
  audit(AUDIT_HOST_NOT, 'affected');

hotfix_check_fversion_init();

var report =
 '\n Nessus cannot locate the registry key ' + key +
 '\n indicating that the Windows Recovery Environment has not been updated as according to KB5025175\n';

hotfix_add_report(report);
hotfix_security_warning();
hotfix_check_fversion_end();
exit(0);
