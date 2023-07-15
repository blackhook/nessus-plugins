#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(168877);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/10");

  script_cve_id(
    "CVE-2022-4436",
    "CVE-2022-4437",
    "CVE-2022-4438",
    "CVE-2022-4439",
    "CVE-2022-4440"
  );
  script_xref(name:"IAVA", value:"2023-A-0003-S");

  script_name(english:"Microsoft Edge (Chromium) < 108.0.1462.54 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 108.0.1462.54. It is, therefore, affected
by multiple vulnerabilities as referenced in the December 16, 2022 advisory.

  - Use after free in Blink Media in Google Chrome prior to 108.0.5359.124 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2022-4436)

  - Use after free in Mojo IPC in Google Chrome prior to 108.0.5359.124 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2022-4437)

  - Use after free in Blink Frames in Google Chrome prior to 108.0.5359.124 allowed a remote attacker who
    convinced the user to engage in specific UI interactions to potentially exploit heap corruption via a
    crafted HTML page. (Chromium security severity: High) (CVE-2022-4438)

  - Use after free in Aura in Google Chrome on Windows prior to 108.0.5359.124 allowed a remote attacker who
    convinced the user to engage in specific UI interactions to potentially exploit heap corruption via
    specific UI interactions. (Chromium security severity: High) (CVE-2022-4439)

  - Use after free in Profiles in Google Chrome prior to 108.0.5359.124 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2022-4440)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://learn.microsoft.com/en-us/deployedge/microsoft-edge-relnotes-security
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?245dfb65");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-4436");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-4437");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-4438");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-4439");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-4440");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 108.0.1462.54 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-4440");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_edge_chromium_installed.nbin");
  script_require_keys("installed_sw/Microsoft Edge (Chromium)", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::get_app_info(app:'Microsoft Edge (Chromium)', win_local:TRUE);

var extended = FALSE;
if (app_info['Channel'] == 'extended') extended = TRUE;

var constraints;
if (!extended) {
	constraints = [
  		{ 'fixed_version' : '108.0.1462.54' }
	];
} else {
	audit(AUDIT_INST_VER_NOT_VULN, 'Microsoft Edge (Chromium)');
};
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
