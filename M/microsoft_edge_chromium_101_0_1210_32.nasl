#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160319);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-1477",
    "CVE-2022-1478",
    "CVE-2022-1479",
    "CVE-2022-1481",
    "CVE-2022-1482",
    "CVE-2022-1483",
    "CVE-2022-1484",
    "CVE-2022-1485",
    "CVE-2022-1486",
    "CVE-2022-1487",
    "CVE-2022-1488",
    "CVE-2022-1490",
    "CVE-2022-1491",
    "CVE-2022-1492",
    "CVE-2022-1493",
    "CVE-2022-1494",
    "CVE-2022-1495",
    "CVE-2022-1497",
    "CVE-2022-1498",
    "CVE-2022-1499",
    "CVE-2022-1500",
    "CVE-2022-1501",
    "CVE-2022-29146",
    "CVE-2022-29147"
  );
  script_xref(name:"IAVA", value:"2022-A-0183-S");

  script_name(english:"Microsoft Edge (Chromium) < 101.0.1210.32 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 101.0.1210.32. It is, therefore, affected
by multiple vulnerabilities as referenced in the April 28, 2022 advisory.

  - Use after free in Dev Tools in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to
    potentially exploit heap corruption via specific and direct user interaction. (CVE-2022-1493)

  - Use after free in Vulkan in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-1477)

  - Use after free in SwiftShader in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-1478)

  - Use after free in ANGLE in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-1479)

  - Use after free in Sharing in Google Chrome on Mac prior to 101.0.4951.41 allowed a remote attacker who
    convinced a user to engage in specific user interaction to potentially exploit heap corruption via a
    crafted HTML page. (CVE-2022-1481)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#april-28-2022
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?436625dd");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1477");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1478");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1479");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1481");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1482");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1483");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1484");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1485");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1486");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1487");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1488");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1490");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1491");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1492");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1493");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1494");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1495");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1497");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1498");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1499");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1500");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1501");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-29146");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-29147");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 101.0.1210.32 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1493");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/28");

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
  { 'fixed_version' : '101.0.1210.32' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
