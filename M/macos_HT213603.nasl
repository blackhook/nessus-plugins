#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170453);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id(
    "CVE-2022-35252",
    "CVE-2023-23497",
    "CVE-2023-23499",
    "CVE-2023-23505",
    "CVE-2023-23508",
    "CVE-2023-23513",
    "CVE-2023-23517",
    "CVE-2023-23518"
  );
  script_xref(name:"APPLE-SA", value:"HT213603");
  script_xref(name:"IAVA", value:"2023-A-0054-S");

  script_name(english:"macOS 11.x < 11.7.3 Multiple Vulnerabilities (HT213603)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 11.x prior to 11.7.3. It is, therefore, affected by
multiple vulnerabilities:

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Ventura 13.2, macOS
    Monterey 12.6.3, tvOS 16.3, Safari 16.3, watchOS 9.3, iOS 16.3 and iPadOS 16.3, macOS Big Sur 11.7.3.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2023-23517,
    CVE-2023-23518)

  - When curl is used to retrieve and parse cookies from a HTTP(S) server, itaccepts cookies using control
    codes that when later are sent back to a HTTPserver might make the server return 400 responses.
    Effectively allowing asister site to deny service to all siblings. (CVE-2022-35252)

  - A logic issue was addressed with improved state management. This issue is fixed in macOS Ventura 13.2,
    macOS Monterey 12.6.3, macOS Big Sur 11.7.3. An app may be able to gain root privileges. (CVE-2023-23497)

  - This issue was addressed by enabling hardened runtime. This issue is fixed in macOS Ventura 13.2, macOS
    Monterey 12.6.3, tvOS 16.3, watchOS 9.3, iOS 16.3 and iPadOS 16.3, macOS Big Sur 11.7.3. An app may be
    able to access user-sensitive data. (CVE-2023-23499)

  - A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in
    macOS Ventura 13.2, macOS Monterey 12.6.3, iOS 15.7.3 and iPadOS 15.7.3, watchOS 9.3, iOS 16.3 and iPadOS
    16.3, macOS Big Sur 11.7.3. An app may be able to access information about a user's contacts.
    (CVE-2023-23505)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213603");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 11.7.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-23518");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-23513");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/24");

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
  { 'fixed_version' : '11.7.3', 'min_version' : '11.0', 'fixed_display' : 'macOS Big Sur 11.7.3' }
];

vcf::apple::macos::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);