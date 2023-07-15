#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159816);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2022-1305",
    "CVE-2022-1306",
    "CVE-2022-1307",
    "CVE-2022-1308",
    "CVE-2022-1309",
    "CVE-2022-1310",
    "CVE-2022-1312",
    "CVE-2022-1313",
    "CVE-2022-1314",
    "CVE-2022-1364",
    "CVE-2022-29144"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/06");
  script_xref(name:"IAVA", value:"2022-A-0156-S");

  script_name(english:"Microsoft Edge (Chromium) < 100.0.1185.44 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 100.0.1185.44. It is, therefore, affected
by multiple vulnerabilities as referenced in the April 15, 2022 advisory.

  - Use after free in tab groups in Google Chrome prior to 100.0.4896.88 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-1313)

  - Use after free in storage in Google Chrome prior to 100.0.4896.88 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-1305)

  - Inappropriate implementation in compositing in Google Chrome prior to 100.0.4896.88 allowed a remote
    attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (CVE-2022-1306)

  - Inappropriate implementation in full screen in Google Chrome on Android prior to 100.0.4896.88 allowed a
    remote attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (CVE-2022-1307)

  - Use after free in BFCache in Google Chrome prior to 100.0.4896.88 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-1308)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#april-15-2022
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84a20f12");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1305");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1306");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1307");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1308");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1309");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1310");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1312");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1313");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1314");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1364");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-29144");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 100.0.1185.44 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1313");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/18");

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
var constraints = [
  { 'fixed_version' : '100.0.1185.44' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
