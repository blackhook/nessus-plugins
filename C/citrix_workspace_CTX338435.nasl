#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158566);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/16");

  script_cve_id("CVE-2022-21825");
  script_xref(name:"IAVA", value:"2022-A-0025-S");

  script_name(english:"Citrix Workspace App for Linux Privilege Escalation (CTX338435)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix Workspace installed on the remote host is affected by a privilege escalation vulnerability. An
improper access control vulnerability exists in Citrix Workspace App for Linux 2012 - 2111 with App Protection installed
that can allow an attacker to perform local privilege escalation.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX338435");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Citrix Workspace App for Linux 2112 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21825");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:workspace");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_workspace_app_nix_installed.nbin");
  script_require_keys("Settings/ParanoidReport", "installed_sw/Citrix Workspace");

  exit(0);
}

include('vcf.inc');


var app_info = vcf::get_app_info(app:'Citrix Workspace');

# Not checking for App Protection config
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

# 2112 = 21.12.0.18, can be seen in filename at:
# https://www.citrix.com/downloads/workspace-app/legacy-workspace-app-for-linux/workspace-app-for-linux-2112.html
var constraints = [
  { 'fixed_version' : '21.12.0.18', 'fixed_display' : '2112 (21.12.0.18)'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
