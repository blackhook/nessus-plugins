##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162227);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-30658",
    "CVE-2022-30659",
    "CVE-2022-30660",
    "CVE-2022-30661",
    "CVE-2022-30662",
    "CVE-2022-30663",
    "CVE-2022-30665"
  );
  script_xref(name:"IAVA", value:"2022-A-0247-S");

  script_name(english:"Adobe InDesign < 16.4.2 / 17.0.0 < 17.3.0 Multiple Arbitrary Code Execution (APSB22-30)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe InDesign instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe InDesign installed on the remote Windows host is prior to 16.4.2, 17.3.0. It is, therefore,
affected by multiple vulnerabilities as referenced in the APSB22-30 advisory.

  - Heap-based Buffer Overflow (CWE-122) potentially leading to Arbitrary code execution (CVE-2022-30658,
    CVE-2022-30661)

  - Out-of-bounds Write (CWE-787) potentially leading to Arbitrary code execution (CVE-2022-30659,
    CVE-2022-30660, CVE-2022-30662, CVE-2022-30663, CVE-2022-30665)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/indesign/apsb22-30.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe InDesign version 16.4.2, 17.3.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-30665");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(122, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:indesign");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_indesign_installed.nbin");
  script_require_keys("installed_sw/Adobe InDesign", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe InDesign', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '16.4.2' },
  { 'min_version' : '17.0.0', 'fixed_version' : '17.3.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
