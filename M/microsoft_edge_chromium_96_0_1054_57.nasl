#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156077);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2021-4098",
    "CVE-2021-4099",
    "CVE-2021-4100",
    "CVE-2021-4101",
    "CVE-2021-4102"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/12/29");
  script_xref(name:"IAVA", value:"2021-A-0576-S");

  script_name(english:"Microsoft Edge (Chromium) < 96.0.1054.57 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 96.0.1054.57. It is, therefore, affected
by multiple vulnerabilities as referenced in the December 14, 2021 advisory.

  - Use after free in V8 in Google Chrome prior to 96.0.4664.110 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-4102)

  - Insufficient data validation in Mojo in Google Chrome prior to 96.0.4664.110 allowed a remote attacker who
    had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (CVE-2021-4098)

  - Use after free in Swiftshader in Google Chrome prior to 96.0.4664.110 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-4099)

  - Object lifecycle issue in ANGLE in Google Chrome prior to 96.0.4664.110 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-4100)

  - Heap buffer overflow in Swiftshader in Google Chrome prior to 96.0.4664.110 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-4101)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#december-14-2021
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f5dd1e14");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-4098");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-4099");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-4100");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-4101");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-4102");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 96.0.1054.57 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4102");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_edge_chromium_installed.nbin");
  script_require_keys("installed_sw/Microsoft Edge (Chromium)", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::get_app_info(app:'Microsoft Edge (Chromium)', win_local:TRUE);
var constraints = [
  { 'fixed_version' : '96.0.1054.57' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
