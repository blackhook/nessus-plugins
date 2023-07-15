#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154173);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/20");

  script_cve_id("CVE-2021-41352");
  script_xref(name:"MSKB", value:"5006871");
  script_xref(name:"MSFT", value:"MS21-5006871");
  script_xref(name:"IAVA", value:"2021-A-0470-S");

  script_name(english:"Security Updates for Microsoft System Center Operations Manager (October 2021)");

  script_set_attribute(attribute:"synopsis", value:
"A web application hosted on the remote Windows system is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft System Center Operations Manager installed on the remote Windows host is affected by an
information disclosure vulnerability. A remote, unauthenticated attacker can exploit this vulnerability by sending a
specially crafted request to an affected SCOM instance in order to reveal file content.");
  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2021-41352
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce956d40");
  # https://support.microsoft.com/en-us/topic/update-for-idor-vulnerability-in-system-center-operations-manager-kb5006871-0e3a513a-ad80-4830-8984-2fc5a40ee7f7
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?352f3785");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for System Center Operations Manager 2012 R2, 2016, and 2019.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41352");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:system_center_operations_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("system_center_operations_mgr_installed.nasl");
  script_require_ports("installed_sw/System Center Operations Manager Server", "installed_sw/System Center Operations Manager 2016 Server", "installed_sw/System Center Operations Manager 2012 Server");

  exit(0);
}

include('vcf_extras_scom.inc');
include('smb_reg_query.inc');

var app_info = vcf::scom::get_app_info();

# Check if Web Console Installed
# we could check keys like
# HKLM\SOFTWARE\Microsoft\System Center Operations Manager\12\Setup\WebConsole\InstallDirectory
# but since we're forking with get_app_info, we should do this way instead.
var install_path = app_info.path - 'Server\\';
var arviewer_file = hotfix_append_path(path:install_path, value:'WebConsole\\AppDiagnostics\\AppAdvisor\\Web\\Bin\\ARViewer.dll');
var arviewer_ver = hotfix_get_fversion(path:arviewer_file);

if ( arviewer_ver.error != HCF_OK )
  audit(AUDIT_PACKAGE_NOT_INSTALLED, 'System Center Operations Manager WebConsole');

app_info.parsed_version = vcf::parse_version(arviewer_ver.version);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'min_version':'7.1.10226.0', 'fixed_version':'7.1.10226.1413' }, # 2012 R2
  { 'min_version':'7.2.11719.0', 'fixed_version':'7.2.12335.0' },    # 2016
  { 'min_version':'10.19.10050.0', 'fixed_version':'10.19.10550.0' } # 2019
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);

