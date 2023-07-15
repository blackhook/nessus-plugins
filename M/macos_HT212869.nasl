#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154711);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2021-30813",
    "CVE-2021-30821",
    "CVE-2021-30823",
    "CVE-2021-30824",
    "CVE-2021-30833",
    "CVE-2021-30861",
    "CVE-2021-30864",
    "CVE-2021-30868",
    "CVE-2021-30873",
    "CVE-2021-30876",
    "CVE-2021-30877",
    "CVE-2021-30879",
    "CVE-2021-30880",
    "CVE-2021-30881",
    "CVE-2021-30883",
    "CVE-2021-30886",
    "CVE-2021-30887",
    "CVE-2021-30888",
    "CVE-2021-30889",
    "CVE-2021-30890",
    "CVE-2021-30892",
    "CVE-2021-30895",
    "CVE-2021-30896",
    "CVE-2021-30899",
    "CVE-2021-30901",
    "CVE-2021-30903",
    "CVE-2021-30905",
    "CVE-2021-30906",
    "CVE-2021-30907",
    "CVE-2021-30908",
    "CVE-2021-30909",
    "CVE-2021-30910",
    "CVE-2021-30911",
    "CVE-2021-30912",
    "CVE-2021-30913",
    "CVE-2021-30915",
    "CVE-2021-30916",
    "CVE-2021-30917",
    "CVE-2021-30919",
    "CVE-2021-30920"
  );
  script_xref(name:"APPLE-SA", value:"HT212869");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2021-10-26-3");
  script_xref(name:"IAVA", value:"2021-A-0505-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/13");

  script_name(english:"macOS 12.x < 12.0.1 (HT212869)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS security update.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 12.x prior to 12.0.1 Monterey. It is, therefore,
affected by multiple vulnerabilities including the following:

  - Exploitation of this vulnerability may lead to arbitrary code execution with kernel privileges. (CVE-2021-30899, 
      CVE-2021-30824, CVE-2021-30901, CVE-2021-30821, CVE-2021-30883, CVE-2021-30886, CVE-2021-30909, CVE-2021-30916, 
      CVE-2021-30868)

  - Exploitation of this vulnerability may lead to elevation of privileges. (CVE-2021-30873, CVE-2021-30907, 
      CVE-2021-30906)

  - Exploitation of this vulnerability may lead to information disclosure. ( CVE-2021-30876, CVE-2021-30879, 
      CVE-2021-30906, CVE-2021-30905, CVE-2021-30895, CVE-2021-30896, CVE-2021-30910, CVE-2021-30911, CVE-2021-30920,
      CVE-2021-30912, CVE-2021-30888)

Note that Nessus has not tested for this issue but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-gb/HT212869");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 12.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30916");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-30889");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/29");

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
var constraints = [{'min_version': '12.0', 'fixed_version': '12.0.1', 'fixed_display': 'macOS Monterey 12.0.1'}];

vcf::apple::macos::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);