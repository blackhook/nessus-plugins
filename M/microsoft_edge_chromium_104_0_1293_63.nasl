#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164293);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/21");

  script_cve_id(
    "CVE-2022-2852",
    "CVE-2022-2853",
    "CVE-2022-2854",
    "CVE-2022-2855",
    "CVE-2022-2857",
    "CVE-2022-2858",
    "CVE-2022-2860",
    "CVE-2022-2861"
  );

  script_name(english:"Microsoft Edge (Chromium) < 104.0.1293.63 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 104.0.1293.63. It is, therefore, affected
by multiple vulnerabilities as referenced in the August 19, 2022 advisory.

  - Use after free in FedCM. (CVE-2022-2852)

  - Heap buffer overflow in Downloads. (CVE-2022-2853)

  - Use after free in SwiftShader. (CVE-2022-2854)

  - Use after free in ANGLE. (CVE-2022-2855)

  - Use after free in Blink. (CVE-2022-2857)

  - Use after free in Sign-In Flow. (CVE-2022-2858)

  - Insufficient policy enforcement in Cookies. (CVE-2022-2860)

  - Inappropriate implementation in Extensions API. (CVE-2022-2861)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#august-19-2022
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4ce23d54");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-2852");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-2853");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-2854");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-2855");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-2857");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-2858");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-2860");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-2861");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 104.0.1293.63 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2858");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_edge_chromium_installed.nbin");
  script_require_keys("installed_sw/Microsoft Edge (Chromium)", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::get_app_info(app:'Microsoft Edge (Chromium)', win_local:TRUE);
var constraints = [
  { 'fixed_version' : '104.0.1293.63' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
