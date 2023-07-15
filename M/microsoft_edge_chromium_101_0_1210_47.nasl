##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161198);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-1634",
    "CVE-2022-1635",
    "CVE-2022-1636",
    "CVE-2022-1637",
    "CVE-2022-1638",
    "CVE-2022-1639",
    "CVE-2022-1640"
  );

  script_name(english:"Microsoft Edge (Chromium) < 101.0.1210.47 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 101.0.1210.47. It is, therefore, affected
by multiple vulnerabilities as referenced in the May 13, 2022 advisory.

  - Use after free in Sharing in Google Chrome prior to 101.0.4951.64 allowed a remote attacker who convinced
    a user to engage in specific UI interactions to potentially exploit heap corruption via a crafted HTML
    page. (CVE-2022-1640)

  - Use after free in Browser UI in Google Chrome prior to 101.0.4951.64 allowed a remote attacker who had
    convinced a user to engage in specific UI interaction to potentially exploit heap corruption via specific
    user interactions. (CVE-2022-1634)

  - Use after free in Permission Prompts in Google Chrome prior to 101.0.4951.64 allowed a remote attacker who
    convinced a user to engage in specific UI interactions to potentially exploit heap corruption via specific
    user interactions. (CVE-2022-1635)

  - Use after free in Performance APIs in Google Chrome prior to 101.0.4951.64 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-1636)

  - Inappropriate implementation in Web Contents in Google Chrome prior to 101.0.4951.64 allowed a remote
    attacker to leak cross-origin data via a crafted HTML page. (CVE-2022-1637)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#may-13-2022
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3405acc7");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1634");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1635");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1636");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1637");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1638");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1639");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1640");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 101.0.1210.47 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1640");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
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
  { 'fixed_version' : '101.0.1210.47' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
