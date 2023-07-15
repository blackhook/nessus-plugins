#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158097);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/03");

  script_cve_id(
    "CVE-2022-0603",
    "CVE-2022-0604",
    "CVE-2022-0605",
    "CVE-2022-0606",
    "CVE-2022-0607",
    "CVE-2022-0608",
    "CVE-2022-0609",
    "CVE-2022-0610"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/01");
  script_xref(name:"IAVA", value:"2022-A-0086-S");

  script_name(english:"Microsoft Edge (Chromium) < 98.0.1108.55 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 98.0.1108.55. It is, therefore, affected
by multiple vulnerabilities as referenced in the February 16, 2022 advisory.

  - Inappropriate implementation in Gamepad API in Google Chrome prior to 98.0.4758.102 allowed a remote
    attacker to potentially exploit heap corruption via a crafted HTML page. (CVE-2022-0610)

  - Use after free in File Manager in Google Chrome on Chrome OS prior to 98.0.4758.102 allowed a remote
    attacker to potentially exploit heap corruption via a crafted HTML page. (CVE-2022-0603)

  - Heap buffer overflow in Tab Groups in Google Chrome prior to 98.0.4758.102 allowed an attacker who
    convinced a user to install a malicious extension and engage in specific user interaction to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-0604)

  - Use after free in Webstore API in Google Chrome prior to 98.0.4758.102 allowed an attacker who convinced a
    user to install a malicious extension and convinced a user to enage in specific user interaction to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-0605)

  - Use after free in ANGLE in Google Chrome prior to 98.0.4758.102 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-0606)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#february-16-2022
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e17239f6");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-0603");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-0604");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-0605");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-0606");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-0607");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-0608");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-0609");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-0610");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 98.0.1108.55 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0610");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { 'fixed_version' : '98.0.1108.55' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
