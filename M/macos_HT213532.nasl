#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168697);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/03");

  script_cve_id(
    "CVE-2022-24836",
    "CVE-2022-29181",
    "CVE-2022-32942",
    "CVE-2022-32943",
    "CVE-2022-42837",
    "CVE-2022-42840",
    "CVE-2022-42841",
    "CVE-2022-42842",
    "CVE-2022-42843",
    "CVE-2022-42845",
    "CVE-2022-42847",
    "CVE-2022-42852",
    "CVE-2022-42853",
    "CVE-2022-42854",
    "CVE-2022-42855",
    "CVE-2022-42856",
    "CVE-2022-42859",
    "CVE-2022-42861",
    "CVE-2022-42862",
    "CVE-2022-42863",
    "CVE-2022-42864",
    "CVE-2022-42865",
    "CVE-2022-42866",
    "CVE-2022-42867",
    "CVE-2022-46689",
    "CVE-2022-46690",
    "CVE-2022-46691",
    "CVE-2022-46692",
    "CVE-2022-46693",
    "CVE-2022-46695",
    "CVE-2022-46696",
    "CVE-2022-46697",
    "CVE-2022-46698",
    "CVE-2022-46699",
    "CVE-2022-46700",
    "CVE-2022-46701",
    "CVE-2022-46704",
    "CVE-2022-46705"
  );
  script_xref(name:"APPLE-SA", value:"HT213532");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/01/04");
  script_xref(name:"IAVA", value:"2022-A-0524-S");

  script_name(english:"macOS 13.x < 13.1 Multiple Vulnerabilities (HT213532)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 13.x prior to 13.1. It is, therefore, affected by
multiple vulnerabilities:

  - Nokogiri is an open source XML and HTML library for Ruby. Nokogiri `< v1.13.4` contains an inefficient
    regular expression that is susceptible to excessive backtracking when attempting to detect encoding in
    HTML documents. Users are advised to upgrade to Nokogiri `>= 1.13.4`. There are no known workarounds for
    this issue. (CVE-2022-24836)

  - Nokogiri is an open source XML and HTML library for Ruby. Nokogiri prior to version 1.13.6 does not type-
    check all inputs into the XML and HTML4 SAX parsers, allowing specially crafted untrusted inputs to cause
    illegal memory access errors (segfault) or reads from unrelated memory. Version 1.13.6 contains a patch
    for this issue. As a workaround, ensure the untrusted input is a `String` by calling `#to_s` or
    equivalent. (CVE-2022-29181)

  - The issue was addressed with improved memory handling. (CVE-2022-32942, CVE-2022-42840, CVE-2022-42842,
    CVE-2022-42845, CVE-2022-42852, CVE-2022-42854)

  - The issue was addressed with improved bounds checks. (CVE-2022-32943, CVE-2022-46701)

  - An issue existed in the parsing of URLs. This issue was addressed with improved input validation.
    (CVE-2022-42837)

  - A type confusion issue was addressed with improved checks. (CVE-2022-42841)

  - This issue was addressed with improved data protection. (CVE-2022-42843)

  - An out-of-bounds write issue was addressed with improved input validation. (CVE-2022-42847,
    CVE-2022-46690, CVE-2022-46693)

  - An access issue was addressed with improved access restrictions. (CVE-2022-42853)

  - A logic issue was addressed with improved state management. (CVE-2022-42855, CVE-2022-46692)

  - A type confusion issue was addressed with improved state handling. (CVE-2022-42856)

  - Multiple issues were addressed by removing the vulnerable code. (CVE-2022-42859)

  - This issue was addressed with improved checks. (CVE-2022-42861)

  - This issue was addressed by removing the vulnerable code. (CVE-2022-42862)

  - A memory corruption issue was addressed with improved state management. (CVE-2022-42863, CVE-2022-46699)

  - A race condition was addressed with improved state handling. (CVE-2022-42864)

  - This issue was addressed by enabling hardened runtime. (CVE-2022-42865)

  - The issue was addressed with improved handling of caches. (CVE-2022-42866)

  - A use after free issue was addressed with improved memory management. (CVE-2022-42867)

  - A race condition was addressed with additional validation. (CVE-2022-46689)

  - A memory consumption issue was addressed with improved memory handling. (CVE-2022-46691)

  - A spoofing issue existed in the handling of URLs. This issue was addressed with improved input validation.
    (CVE-2022-46695)

  - A memory corruption issue was addressed with improved input validation. (CVE-2022-46696, CVE-2022-46700)

  - An out-of-bounds access issue was addressed with improved bounds checking. (CVE-2022-46697)

  - A logic issue was addressed with improved checks. (CVE-2022-46698)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213532");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 13.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29181");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-42842");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'macOS Dirty Cow Arbitrary File Write Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();

var constraints = [
  { 'fixed_version' : '13.1.0', 'min_version' : '13.0', 'fixed_display' : 'macOS Ventura 13.1' }
];

vcf::apple::macos::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
