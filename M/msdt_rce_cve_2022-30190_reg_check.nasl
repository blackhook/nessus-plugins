##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161691);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/28");

  script_name(english:"The Microsoft Windows Support Diagnostic Tool (MSDT) RCE Workaround Detection (CVE-2022-30190)");

  script_set_attribute(attribute:"synopsis", value:
"Checks for the HKEY_CLASSES_ROOT\ms-msdt registry key.");
  script_set_attribute(attribute:"description", value:
"The remote host has the HKEY_CLASSES_ROOT\ms-msdt registry key. This is a known exposure for CVE-2022-30190.

Note that Nessus has not tested for CVE-2022-30190. It is only checking if the registry key exists. The recommendation is
to apply the latest patch.");
  # https://community.tenable.com/s/article/Microsoft-CVE-2022-30190-Patch-and-Workaround-Plugin-Advisement
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?440e4ba1");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30190
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30190");
  # https://msrc-blog.microsoft.com/2022/05/30/guidance-for-cve-2022-30190-microsoft-support-diagnostic-tool-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9345997");
  script_set_attribute(attribute:"solution", value:
"Apply the latest Cumulative Update.");

  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:msdt");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_windows_defender_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');
include('smb_reg_query.inc');
include('spad_log_func.inc');
include('smb_func.inc');

registry_init();
var hkcr = registry_hive_connect(hive:HKEY_CLASS_ROOT, exit_on_fail:TRUE);

if (!registry_key_exists(handle:hkcr, key:'ms-msdt'))
{
  spad_log(message:'HKEY_CLASSES_ROOT\\ms-msdt does not exist, auditing');
  close_registry();
  audit(AUDIT_OS_CONF_NOT_VULN, 'Windows');
}

var report = 'The HKEY_CLASSES_ROOT\\ms-msdt registry key exists on the target. This may indicate that the target is' +
  ' vulnerable to CVE-2022-30190, if the vendor patch is not applied.';

var port = kb_smb_transport();
close_registry();
security_report_v4(severity:SECURITY_NOTE, extra:report, port:port);
exit(0);
