#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170626);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/26");

  script_cve_id("CVE-2021-26414");

  script_name(english:"KB5004442: Windows DCOM Server Security Feature Bypass Registry Check (CVE-2021-26414)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host DCOM hardening measure is disabled.");
  script_set_attribute(attribute:"description", value:
"The remote Windows DCOM Server may be in a vulnerable state to exploitation by having the 
HKLM\Software\Microsoft\Ole\AppCompat\RequireIntegrityActivationAuthenticationLevel registry value set 
to 0. Hardening changes in DCOM were required for CVE-2021-26414 and were implemented in 2 phases on 
June 8, 2021 and June 14, 2022 as described in KB5004442. Without upcoming March 2023 Microsoft upgrade 
DCOM hardening can be manually disabled by setting this registry value to 0 on the server side to help 
mitigate compatibility issues. This presents a vulnerability risk and should be avoided.");
  # https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ffd83ea3");
  script_set_attribute(attribute:"solution", value:
"Update the DWORD registry value RequireIntegrityActivationAuthenticationLevel under: 
HKEY_LOCAL_MACHINE\Software\Microsoft\Ole\AppCompat to 1 to enable DCOM hardening");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26414");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) 
  audit(AUDIT_SHARE_FAIL, share);

hotfix_check_fversion_init();
registry_init();
var hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
var key = "SOFTWARE\Microsoft\Ole\AppCompat\RequireIntegrityActivationAuthenticationLevel";
var value = get_registry_value(handle:hklm, item:key);
RegCloseKey(handle:hklm);

if (!isnull(value) && value == 0)
{
  var report = '\n Nessus detected the following insecure registry key configuration:\n';
  report += '    - ' + key + ' is present in the registry with value ' + value + '\n';

  hotfix_add_report(report);

  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
