#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159105);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/08");

  script_cve_id(
    "CVE-2022-22582",
    "CVE-2022-22597",
    "CVE-2022-22599",
    "CVE-2022-22613",
    "CVE-2022-22614",
    "CVE-2022-22615",
    "CVE-2022-22616",
    "CVE-2022-22617",
    "CVE-2022-22625",
    "CVE-2022-22626",
    "CVE-2022-22627",
    "CVE-2022-22631",
    "CVE-2022-22632",
    "CVE-2022-22633",
    "CVE-2022-22638",
    "CVE-2022-22647",
    "CVE-2022-22648",
    "CVE-2022-22650",
    "CVE-2022-22656",
    "CVE-2022-22661",
    "CVE-2022-22662"
  );
  script_xref(name:"APPLE-SA", value:"HT213184");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2022-03-14-5");
  script_xref(name:"IAVA", value:"2022-A-0118-S");

  script_name(english:"macOS 11.x < 11.6.5 Multiple Vulnerabilities (HT213184)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS security update.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 11.x prior to 11.6.5 Big Sur. It is, therefore,
affected by multiple vulnerabilities including the following:

  - Opening a maliciously crafted PDF file may lead to an unexpected application termination or arbitrary code
    execution. (CVE-2022-22633)

  - Processing a maliciously crafted AppleScript binary may result in unexpected application termination or
    disclosure of process memory. (CVE-2022-22626, CVE-2022-22627)

  - A local attacker may be able to view the previous logged in user's desktop from the fast user switching
    screen. (CVE-2022-22579)

Note that Nessus has not tested for this issue but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213184");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 11.6.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22661");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-22632");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'macOS Gatekeeper check bypass');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();
var constraints = [{ 'min_version' : '11.0', 'fixed_version' : '11.6.5', 'fixed_display' : 'macOS Big Sur 11.6.5' }];

vcf::apple::macos::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
