##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144453);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id(
    "CVE-2020-9943",
    "CVE-2020-9944",
    "CVE-2020-9956",
    "CVE-2020-9960",
    "CVE-2020-9962",
    "CVE-2020-9967",
    "CVE-2020-9974",
    "CVE-2020-9975",
    "CVE-2020-9978",
    "CVE-2020-10002",
    "CVE-2020-10004",
    "CVE-2020-10007",
    "CVE-2020-10009",
    "CVE-2020-10010",
    "CVE-2020-10012",
    "CVE-2020-10014",
    "CVE-2020-10015",
    "CVE-2020-10016",
    "CVE-2020-10017",
    "CVE-2020-13524",
    "CVE-2020-15969",
    "CVE-2020-27896",
    "CVE-2020-27897",
    "CVE-2020-27898",
    "CVE-2020-27901",
    "CVE-2020-27903",
    "CVE-2020-27906",
    "CVE-2020-27907",
    "CVE-2020-27908",
    "CVE-2020-27910",
    "CVE-2020-27911",
    "CVE-2020-27912",
    "CVE-2020-27914",
    "CVE-2020-27915",
    "CVE-2020-27916",
    "CVE-2020-27919",
    "CVE-2020-27920",
    "CVE-2020-27921",
    "CVE-2020-27922",
    "CVE-2020-27923",
    "CVE-2020-27924",
    "CVE-2020-27926",
    "CVE-2020-27931",
    "CVE-2020-27941",
    "CVE-2020-27943",
    "CVE-2020-27944",
    "CVE-2020-27946",
    "CVE-2020-27947",
    "CVE-2020-27948",
    "CVE-2020-27949",
    "CVE-2020-27952",
    "CVE-2020-29611",
    "CVE-2020-29612",
    "CVE-2020-29616",
    "CVE-2020-29617",
    "CVE-2020-29618",
    "CVE-2020-29619",
    "CVE-2020-29620",
    "CVE-2020-29621"
  );
  script_xref(name:"APPLE-SA", value:"HT212011");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2020-12-14");
  script_xref(name:"IAVA", value:"2020-A-0576-S");

  script_name(english:"macOS 10.14.x < 10.14.6 Security Update 2020-007 / 10.15.x < 10.15.7 Security Update 2020-001 / macOS 11.x < 11.1 (HT212011)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS security update.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 10.14.x prior to 10.14.6 Security Update 2020-007
Mojave, 10.15.x prior to 10.15.7 Security Update 2020-001 Catalina, or 11.x prior to 11.1. It is, therefore, affected by
multiple vulnerabilities, including the following:

  - Processing a maliciously crafted audio file may lead to arbitrary code execution. (CVE-2020-9960,
    CVE-2020-10017, CVE-2020-27908, CVE-2020-27910, CVE-2020-27916, CVE-2020-27948)

  - Processing a maliciously crafted image may lead to arbitrary code execution. (CVE-2020-9962,
    CVE-2020-27912, CVE-2020-27919, CVE-2020-27923, CVE-2020-27924, CVE-2020-29611, CVE-2020-29616,
    CVE-2020-29618)

  - Processing a maliciously crafted font file may lead to arbitrary code execution. (CVE-2020-9956,
    CVE-2020-27922, CVE-2020-27931, CVE-2020-27943, CVE-2020-27944, CVE-2020-27952)

Note that Nessus has not tested for this issue but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT212011");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 10.14.6 Security Update 2020-007 / 10.15.7 Security Update 2020-001 / macOS 11.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9975");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-27920");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_apple.inc');

app_info = vcf::apple::macos::get_app_info();

constraints = [
  { 'max_version' : '10.14.6', 'min_version' : '10.14', 'fixed_build': '18G7016', 'fixed_display' : '10.14.6 Security Update 2020-007 Mojave' },
  { 'max_version' : '10.15.7', 'min_version' : '10.15', 'fixed_build': '19H114', 'fixed_display' : '10.15.7 Security Update 2020-001 Catalina' },
  { 'min_version' : '11.0', 'fixed_version' : '11.1', 'fixed_display' : 'macOS Big Sur 11.1' }
];

vcf::apple::macos::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
