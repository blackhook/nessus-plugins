#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157181);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/26");

  script_cve_id(
    "CVE-2021-30946",
    "CVE-2021-30972",
    "CVE-2022-22579",
    "CVE-2022-22583",
    "CVE-2022-22593"
  );
  script_xref(name:"APPLE-SA", value:"HT213056");
  script_xref(name:"IAVA", value:"2022-A-0051-S");

  script_name(english:"macOS 10.15.x < Catalina Security Update 2022-001 (HT213056)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS or Mac OS X security update or supplemental update that fixes multiple
vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 0.0.x prior to Catalina Security Update 2022-001
Catalina. It is, therefore, affected by multiple vulnerabilities :

  - A logic issue was addressed with improved restrictions. This issue is fixed in macOS Monterey 12.1,
    watchOS 8.3, iOS 15.2 and iPadOS 15.2, macOS Big Sur 11.6.2. A malicious application may be able to bypass
    certain Privacy preferences. (CVE-2021-30946)

  - A buffer overflow issue was addressed with improved memory handling. A malicious application may be able 
    to execute arbitrary code with kernel privileges. (CVE-2022-22593)

  - An information disclosure issue was addressed with improved state management. Processing a maliciously 
    crafted STL file may lead to unexpected application termination or arbitrary code execution (CVE-2022-22579)

Note that Nessus has not tested for this issue but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213056");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS Catalina Security Update 2022-001 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22593");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/local_checks_enabled", "Host/MacOSX/Version", "Host/MacOSX/packages/boms");

  exit(0);
}
include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();

var constraints = [
  {
    'min_version': '10.15',
    'max_version': '10.15.7', 
    'fixed_build'  : '19H1713', 
    'fixed_display': 'Catalina 10.15.7 Security Update 2022-001'
  }
];

vcf::apple::macos::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
