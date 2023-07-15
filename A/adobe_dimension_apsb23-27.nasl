#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174124);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/14");

  script_cve_id(
    "CVE-2023-26371",
    "CVE-2023-26372",
    "CVE-2023-26373",
    "CVE-2023-26374",
    "CVE-2023-26375",
    "CVE-2023-26376",
    "CVE-2023-26377",
    "CVE-2023-26378",
    "CVE-2023-26379",
    "CVE-2023-26380",
    "CVE-2023-26381",
    "CVE-2023-26382",
    "CVE-2023-26400",
    "CVE-2023-26401",
    "CVE-2023-26404"
  );
  script_xref(name:"IAVA", value:"2023-A-0196");

  script_name(english:"Adobe Dimension < 3.4.9 Multiple Vulnerabilities (APSB23-27)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Dimension instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Dimension installed on the remote Windows host is prior to 3.4.9. It is, therefore, affected by
multiple vulnerabilities as referenced in the APSB23-27 advisory.

  - Out-of-bounds Write (CWE-787) potentially leading to Arbitrary code execution (CVE-2023-26372,
    CVE-2023-26373)

  - Out-of-bounds Read (CWE-125) potentially leading to Arbitrary code execution (CVE-2023-26374)

  - Out-of-bounds Read (CWE-125) potentially leading to Memory leak (CVE-2023-26371, CVE-2023-26375,
    CVE-2023-26376, CVE-2023-26377, CVE-2023-26378, CVE-2023-26379, CVE-2023-26380, CVE-2023-26381,
    CVE-2023-26382, CVE-2023-26400, CVE-2023-26401, CVE-2023-26404)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/dimension/apsb23-27.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Dimension version 3.4.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-26404");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(125, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:dimension");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_dimension_installed.nbin");
  script_require_keys("installed_sw/Adobe Dimension", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Dimension', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '3.4.9' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
