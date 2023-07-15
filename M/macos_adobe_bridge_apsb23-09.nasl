#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171518);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/17");

  script_cve_id(
    "CVE-2023-21583",
    "CVE-2023-22226",
    "CVE-2023-22227",
    "CVE-2023-22228",
    "CVE-2023-22229",
    "CVE-2023-22230",
    "CVE-2023-22231"
  );
  script_xref(name:"IAVA", value:"2023-A-0100");

  script_name(english:"Adobe Bridge 13.x < 13.0.2 / 12.x < 12.0.4 Multiple Vulnerabilities (APSB23-09)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Bridge installed on remote macOS or Mac OS X host is affected by a multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Bridge installed on the remote macOS or Mac OS X host is prior to 13.0.2 or 12.0.4. It is,
therefore, affected by multiple vulnerabilities as referenced in the apsb23-09 advisory.

  - Out-of-bounds Read (CWE-125) potentially leading to Memory leak (CVE-2023-21583, CVE-2023-22231)

  - Stack-based Buffer Overflow (CWE-121) potentially leading to Arbitrary code execution (CVE-2023-22226)

  - Out-of-bounds Write (CWE-787) potentially leading to Arbitrary code execution (CVE-2023-22227,
    CVE-2023-22229, CVE-2023-22230)

  - Improper Input Validation (CWE-20) potentially leading to Arbitrary code execution (CVE-2023-22228)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/bridge/apsb23-09.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Bridge version 13.0.2 or 12.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22230");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 121, 125, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:bridge");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_bridge_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Bridge");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

get_kb_item_or_exit('Host/MacOSX/Version');

var app_info = vcf::get_app_info(app:'Adobe Bridge');

var constraints = [
  { 'min_version' : '12.0.0', 'fixed_version' : '12.0.4' },
  { 'min_version' : '13.0.0', 'fixed_version' : '13.0.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
