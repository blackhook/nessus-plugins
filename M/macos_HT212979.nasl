#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156222);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2021-30767",
    "CVE-2021-30927",
    "CVE-2021-30929",
    "CVE-2021-30931",
    "CVE-2021-30935",
    "CVE-2021-30937",
    "CVE-2021-30938",
    "CVE-2021-30939",
    "CVE-2021-30940",
    "CVE-2021-30941",
    "CVE-2021-30942",
    "CVE-2021-30945",
    "CVE-2021-30946",
    "CVE-2021-30947",
    "CVE-2021-30949",
    "CVE-2021-30950",
    "CVE-2021-30958",
    "CVE-2021-30959",
    "CVE-2021-30961",
    "CVE-2021-30963",
    "CVE-2021-30965",
    "CVE-2021-30968",
    "CVE-2021-30969",
    "CVE-2021-30970",
    "CVE-2021-30971",
    "CVE-2021-30973",
    "CVE-2021-30975",
    "CVE-2021-30976",
    "CVE-2021-30977",
    "CVE-2021-30979",
    "CVE-2021-30980",
    "CVE-2021-30981",
    "CVE-2021-30982",
    "CVE-2021-30990",
    "CVE-2021-30995"
  );
  script_xref(name:"APPLE-SA", value:"HT212979");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2021-12-15-3");
  script_xref(name:"IAVA", value:"2021-A-0577-S");

  script_name(english:"macOS 11.x < 11.6.2 (HT212979)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS security update.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 11.x prior to 11.6.2 Big Sur. It is, therefore,
affected by multiple vulnerabilities including the following:

  - A buffer overflow issue was addressed with improved memory handling. Processing a maliciously crafted USD 
    file may lead to unexpected application termination or arbitrary code execution. (CVE-2021-30979)

  - An out-of-bounds read was addressed with improved input validation. Playing a malicious audio file may 
    lead to arbitrary code execution. (CVE-2021-30958)

  - An out-of-bounds write issue was addressed with improved bounds checking. Processing a maliciously 
    crafted USD file may disclose memory contents. (CVE-2021-30929)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT201222");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 11.6.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30981");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-30935");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}
include('vcf.inc');
include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();
var constraints = [{'min_version': '11.0', 'fixed_version': '11.6.2', 'fixed_display': 'macOS Big Sur 11.6.2'}];

vcf::apple::macos::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
