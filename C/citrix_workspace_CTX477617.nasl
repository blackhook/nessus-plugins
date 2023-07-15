#%NASL_MIN_LEVEL 80900
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171597);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/27");

  script_cve_id("CVE-2023-24484", "CVE-2023-24485");
  script_xref(name:"IAVA", value:"2023-A-0080");

  script_name(english:"Citrix Workspace App for Windows Multiple Vulnerabilities (CTX477617)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix Workspace App installed on the remote host is prior to 1912 LTSR CU7 Hotfix 2, 2203 LTSR CU2 or
2212. It is therefore affected by multiple vulnerabilities as described in the CTX477617 advisory:

  - A local attacker can elevate privileges to those of an Administrator or SYSTEM process if they access
    system while a vulnerable version of Citrix Workspace App is being installed or uninstalled.
    (CVE-2023-24485)

  - A local attacker can cause log files to be written to a directory they do not have permission to write to
    if they have access to the system before vulnerable version of Citrix Workspace App is installed or
    uninstalled by a SYSTEM process. (CVE-2023-24484)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX477617");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Citrix Workspace App versions 1912 LTSR CU7 Hotfix 2, 2203 LTSR CU2, 2212 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24485");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:workspace");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_workspace_win_installed.nbin");
  script_require_keys("installed_sw/Citrix Workspace", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Citrix Workspace');

# Versions available for download have an extra build number in part 4 but we see a little variation here
# so just relying on the parts used for the user-facing number
var constraints = [
  { 'min_version' : '0.0.0.0', 'max_version' : '19.12.0.0', 'fixed_display' : '2212' },
  { 'min_version' : '19.12.0.0', 'fixed_version' : '19.12.7002.0', 'fixed_display' : '1912 LTSR CU7 Hotfix 2' },
  { 'min_version' : '19.13.0.0', 'max_version' : '22.02.0.0', 'fixed_display' : '2212' },
  { 'min_version' : '22.02.0.0', 'fixed_version' : '22.02.2000.0', 'fixed_display' : '2203 LTSR CU2' },
  { 'min_version' : '22.04.0.0', 'fixed_version' : '22.12.0000.0', 'fixed_display' : '2212' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
