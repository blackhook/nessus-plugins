#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173439);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/15");

  script_cve_id(
    "CVE-2023-0433",
    "CVE-2023-0512",
    "CVE-2023-23514",
    "CVE-2023-23527",
    "CVE-2023-23533",
    "CVE-2023-23538",
    "CVE-2023-23540",
    "CVE-2023-23542",
    "CVE-2023-27933",
    "CVE-2023-27935",
    "CVE-2023-27936",
    "CVE-2023-27937",
    "CVE-2023-27942",
    "CVE-2023-27944",
    "CVE-2023-27946",
    "CVE-2023-27949",
    "CVE-2023-27951",
    "CVE-2023-27953",
    "CVE-2023-27955",
    "CVE-2023-27958",
    "CVE-2023-27961",
    "CVE-2023-27962",
    "CVE-2023-27963",
    "CVE-2023-28178",
    "CVE-2023-28182",
    "CVE-2023-28192",
    "CVE-2023-28200"
  );
  script_xref(name:"APPLE-SA", value:"HT213677");
  script_xref(name:"IAVA", value:"2023-A-0162-S");

  script_name(english:"macOS 12.x < 12.6.4 Multiple Vulnerabilities (HT213677)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 12.x prior to 12.6.4. It is, therefore, affected by
multiple vulnerabilities:

  - A use after free issue was addressed with improved memory management. This issue is fixed in macOS Ventura
    13.2.1, iOS 16.3.1 and iPadOS 16.3.1. An app may be able to execute arbitrary code with kernel
    privileges.. (CVE-2023-23514)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1225. (CVE-2023-0433)

  - Divide By Zero in GitHub repository vim/vim prior to 9.0.1247. (CVE-2023-0512)

  - The issue was addressed with improved memory handling. (CVE-2023-23540, CVE-2023-27933, CVE-2023-27953,
    CVE-2023-27958)

  - The issue was addressed with improved checks. (CVE-2023-23527, CVE-2023-27942, CVE-2023-27951,
    CVE-2023-27955)

  - Multiple validation issues were addressed with improved input sanitization. (CVE-2023-27961)

  - An out-of-bounds write issue was addressed with improved input validation. (CVE-2023-27936)

  - The issue was addressed with improved bounds checks. (CVE-2023-27935)

  - An integer overflow was addressed with improved input validation. (CVE-2023-27937)

  - An out-of-bounds read was addressed with improved bounds checking. (CVE-2023-27946)

  - A validation issue was addressed with improved input sanitization. (CVE-2023-28200)

  - An out-of-bounds read was addressed with improved input validation. (CVE-2023-27949)

  - The issue was addressed with improved authentication. (CVE-2023-28182)

  - A logic issue was addressed with improved checks. (CVE-2023-23533, CVE-2023-23538, CVE-2023-27962)

  - A logic issue was addressed with improved validation. (CVE-2023-28178)

  - The issue was addressed with additional permissions checks. (CVE-2023-27963)

  - A privacy issue was addressed with improved private data redaction for log entries. (CVE-2023-23542)

  - This issue was addressed with a new entitlement. (CVE-2023-27944)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213677");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 12.6.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-27953");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/27");

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
  { 'fixed_version' : '12.6.4', 'min_version' : '12.0', 'fixed_display' : 'macOS Monterey 12.6.4' }
];

vcf::apple::macos::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
