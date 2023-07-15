##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162182);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-30650",
    "CVE-2022-30651",
    "CVE-2022-30652",
    "CVE-2022-30653",
    "CVE-2022-30654",
    "CVE-2022-30655",
    "CVE-2022-30656",
    "CVE-2022-30657"
  );
  script_xref(name:"IAVA", value:"2022-A-0246-S");

  script_name(english:"Adobe InCopy < 16.4.2 / 17.0 < 17.3 Multiple Vulnerabilities Arbitrary code execution (APSB22-29)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe InCopy instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe InCopy installed on the remote host is prior to 16.4.2, 17.3. It is, therefore, affected by
multiple vulnerabilities as referenced in the APSB22-29 advisory.

  - Heap-based Buffer Overflow (CWE-122) potentially leading to Arbitrary code execution (CVE-2022-30650,
    CVE-2022-30654)

  - Out-of-bounds Read (CWE-125) potentially leading to Arbitrary code execution (CVE-2022-30651)

  - Out-of-bounds Write (CWE-787) potentially leading to Arbitrary code execution (CVE-2022-30652,
    CVE-2022-30653, CVE-2022-30656)

  - Use After Free (CWE-416) potentially leading to Arbitrary code execution (CVE-2022-30655, CVE-2022-30657)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/incopy/apsb22-29.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe InCopy version 16.4.2, 17.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-30657");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(122, 125, 416, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:incopy");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_incopy_win_installed.nbin", "adobe_incopy_mac_installed.nbin");
  script_require_keys("installed_sw/Adobe InCopy");

  exit(0);
}

include('vcf.inc');

var app = 'Adobe InCopy';
var win_local;

if (!empty_or_null(get_kb_item('SMB/Registry/Enumerated')))
  win_local = TRUE;
else
  win_local = FALSE;

var app_info = vcf::get_app_info(app:app, win_local:win_local);

var constraints = [
  { 'fixed_version' : '16.4.2' },
  { 'min_version' : '17.0', 'fixed_version' : '17.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
