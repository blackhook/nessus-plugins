#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176078);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/07");

  script_cve_id(
    "CVE-2023-27930",
    "CVE-2023-27940",
    "CVE-2023-28191",
    "CVE-2023-28202",
    "CVE-2023-28204",
    "CVE-2023-32352",
    "CVE-2023-32355",
    "CVE-2023-32357",
    "CVE-2023-32360",
    "CVE-2023-32363",
    "CVE-2023-32367",
    "CVE-2023-32368",
    "CVE-2023-32371",
    "CVE-2023-32372",
    "CVE-2023-32373",
    "CVE-2023-32375",
    "CVE-2023-32376",
    "CVE-2023-32380",
    "CVE-2023-32382",
    "CVE-2023-32384",
    "CVE-2023-32385",
    "CVE-2023-32386",
    "CVE-2023-32387",
    "CVE-2023-32388",
    "CVE-2023-32389",
    "CVE-2023-32390",
    "CVE-2023-32391",
    "CVE-2023-32392",
    "CVE-2023-32394",
    "CVE-2023-32395",
    "CVE-2023-32397",
    "CVE-2023-32398",
    "CVE-2023-32399",
    "CVE-2023-32400",
    "CVE-2023-32402",
    "CVE-2023-32403",
    "CVE-2023-32404",
    "CVE-2023-32405",
    "CVE-2023-32407",
    "CVE-2023-32408",
    "CVE-2023-32409",
    "CVE-2023-32410",
    "CVE-2023-32411",
    "CVE-2023-32412",
    "CVE-2023-32413",
    "CVE-2023-32414",
    "CVE-2023-32415",
    "CVE-2023-32420",
    "CVE-2023-32422",
    "CVE-2023-32423"
  );
  script_xref(name:"APPLE-SA", value:"HT213758");
  script_xref(name:"IAVA", value:"2023-A-0264-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/12");

  script_name(english:"macOS 13.x < 13.4 Multiple Vulnerabilities (HT213758)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 13.x prior to 13.4. It is, therefore, affected by
multiple vulnerabilities:

  - A privacy issue was addressed with improved private data redaction for log entries. (CVE-2023-32388,
    CVE-2023-32392)

  - This issue was addressed with improved checks. (CVE-2023-32400)

  - This issue was addressed with improved entitlements. (CVE-2023-32367, CVE-2023-32376, CVE-2023-32404,
    CVE-2023-32411)

  - The issue was addressed with improved checks. (CVE-2023-32371, CVE-2023-32390, CVE-2023-32391,
    CVE-2023-32394)

  - A privacy issue was addressed with improved handling of temporary files. (CVE-2023-32386)

  - The issue was addressed with improved handling of caches. (CVE-2023-32399, CVE-2023-32408)

  - This issue was addressed with improved redaction of sensitive information. (CVE-2023-28191)

  - An authentication issue was addressed with improved state management. (CVE-2023-32360)

  - A use-after-free issue was addressed with improved memory management. (CVE-2023-32373, CVE-2023-32387,
    CVE-2023-32398, CVE-2023-32412)

  - An out-of-bounds read was addressed with improved input validation. (CVE-2023-28204, CVE-2023-32368,
    CVE-2023-32372, CVE-2023-32375, CVE-2023-32382, CVE-2023-32402, CVE-2023-32410, CVE-2023-32420)

  - A buffer overflow was addressed with improved bounds checking. (CVE-2023-32384)

  - A type confusion issue was addressed with improved checks. (CVE-2023-27930)

  - The issue was addressed with additional permissions checks. (CVE-2023-27940)

  - A logic issue was addressed with improved checks. (CVE-2023-32352, CVE-2023-32405)

  - A logic issue was addressed with improved state management. (CVE-2023-32355, CVE-2023-32369,
    CVE-2023-32395, CVE-2023-32397, CVE-2023-32407)

  - An out-of-bounds write issue was addressed with improved bounds checking. (CVE-2023-32380)

  - This issue was addressed with improved redaction of sensitive information. (CVE-2023-32389,
    CVE-2023-32403, CVE-2023-32415)

  - A denial-of-service issue was addressed with improved memory handling. (CVE-2023-32385)

  - An authorization issue was addressed with improved state management. (CVE-2023-32357)

  - This issue was addressed by adding additional SQLite logging restrictions. (CVE-2023-32422)

  - This issue was addressed with improved state management. (CVE-2023-28202)

  - A buffer overflow issue was addressed with improved memory handling. (CVE-2023-32423)

  - The issue was addressed with improved bounds checks. (CVE-2023-32409)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213758");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 13.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32412");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();

var constraints = [
  { 'fixed_version' : '13.4.0', 'min_version' : '13.0', 'fixed_display' : 'macOS Ventura 13.4' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'sqli':TRUE}
);
