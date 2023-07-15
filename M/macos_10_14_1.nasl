#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(118574);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/16");

  script_cve_id(
    "CVE-2018-3640",
    "CVE-2018-4340",
    "CVE-2018-4342",
    "CVE-2018-4368",
    "CVE-2018-4369",
    "CVE-2018-4371",
    "CVE-2018-4389",
    "CVE-2018-4398",
    "CVE-2018-4400",
    "CVE-2018-4402",
    "CVE-2018-4403",
    "CVE-2018-4410",
    "CVE-2018-4413",
    "CVE-2018-4415",
    "CVE-2018-4419",
    "CVE-2018-4420",
    "CVE-2018-4422",
    "CVE-2018-4423",
    "CVE-2018-4424",
    "CVE-2018-4425"
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2018-10-30-2");
  script_xref(name:"IAVA", value:"2021-A-0356-S");

  script_name(english:"macOS 10.14.x < 10.14.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple security
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is
10.14.x prior to 10.14.1. It is, therefore, affected by multiple
vulnerabilities related to the following components :

  -AppleGraphicsControl
  -CoreAnimation
  -CoreCrypto
  -Dock
  -dyld
  -EFI
  -ICU
  -IOGraphics
  -IOKit
  -IPSec
  -Kernel
  -Mail
  -Microcode
  -NetworkExtension
  -Security
  -WiFi

Note that successful exploitation of the most serious issues can
result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT209193");
  # https://lists.apple.com/archives/security-announce/2018/Oct/msg00003.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f0681c90");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS version 10.14.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-4425");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-4422");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/31");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/OS");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


fix = "10.14.1";
minver = "10.14";

os = get_kb_item("Host/MacOSX/Version");
if (!os)
{
  os = get_kb_item_or_exit("Host/OS");
  if ("Mac OS X" >!< os) audit(AUDIT_OS_NOT, "macOS / Mac OS X");

  c = get_kb_item("Host/OS/Confidence");
  if (c <= 70) exit(1, "Can't determine the host's OS with sufficient confidence.");
}
if (!os) audit(AUDIT_OS_NOT, "macOS / Mac OS X");

matches = pregmatch(pattern:"Mac OS X ([0-9]+(\.[0-9]+)+)", string:os);
if (empty_or_null(matches)) exit(1, "Failed to parse the macOS / Mac OS X version ('" + os + "').");

version = matches[1];

if (ver_compare(ver:version, minver:minver, fix:fix, strict:FALSE) == -1)
{
  security_report_v4(
    port:0,
    severity:SECURITY_HOLE,
    extra:
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n'
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "macOS / Mac OS X", version);
