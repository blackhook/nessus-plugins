##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(140758);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/23");

  script_cve_id("CVE-2020-8207");
  script_xref(name:"IAVA", value:"2020-A-0496-S");

  script_name(english:"Citrix Workspace App for Windows Security Update Privilege Escalation Vulnerability (CTX277662)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix Workspace installed on the remote host is affected by a privilege escalation vulnerability in the
the automatic update service due to improper access control. An authenticated, remote attacker can exploit this issue,
to gain administrator access to the system.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX277662");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Citrix Workspace App 1912 LTSR CU1 Hotfix 1 (19.12.1001) and later cumulative updates, Citrix Workspace App
2008 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8207");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:workspace");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_workspace_win_installed.nbin");
  script_require_keys("Settings/ParanoidReport", "installed_sw/Citrix Workspace");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Citrix Workspace');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Affected versions
# Citrix Workspace app 2002, 2006 and 2006.1 for Windows
# Citrix Workspace app 1912 LTSR for Windows (before CU1 Hotfix 1)
var constraints = [
  { 'min_version' : '19.12.0.0', 'fixed_version' : '19.12.1001.0' },
  { 'min_version' : '20.2.0.0', 'fixed_version' : '20.8.0.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
