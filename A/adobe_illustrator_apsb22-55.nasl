#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164984);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2022-38408", "CVE-2022-38409", "CVE-2022-38410");
  script_xref(name:"IAVA", value:"2022-A-0364-S");

  script_name(english:"Adobe Illustrator 26.x < 26.5 / 25.x < 25.4.8 Multiple Vulnerabilities (APSB22-55)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Illustrator installed on remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Illustrator installed on the remote Windows host is prior to 25.4.8 or 26.5. It is, therefore,
affected by multiple vulnerabilities as referenced in the apsb22-55 advisory.

  - Improper Input Validation (CWE-20) potentially leading to Arbitrary code execution (CVE-2022-38408)

  - Out-of-bounds Read (CWE-125) potentially leading to Memory Leak (CVE-2022-38409, CVE-2022-38410)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/illustrator/apsb22-55.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Illustrator version 25.4.8 or 26.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-38408");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 125);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:illustrator");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_illustrator_installed.nasl");
  script_require_keys("SMB/Adobe Illustrator/Installed");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Illustrator', win_local:TRUE);

var constraints = [
  { 'min_version' : '25.0.0', 'max_version' : '25.4.7', 'fixed_version' : '25.4.8' },
  { 'min_version' : '26.0', 'max_version' : '26.4', 'fixed_version' : '26.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
