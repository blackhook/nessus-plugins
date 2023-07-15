#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(118178);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2016-0702",
    "CVE-2015-3194",
    "CVE-2015-5333",
    "CVE-2015-5334",
    "CVE-2016-1777",
    "CVE-2017-12613",
    "CVE-2017-12618",
    "CVE-2018-3639",
    "CVE-2018-3646",
    "CVE-2018-4126",
    "CVE-2018-4153",
    "CVE-2018-4203",
    "CVE-2018-4295",
    "CVE-2018-4304",
    "CVE-2018-4308",
    "CVE-2018-4310",
    "CVE-2018-4321",
    "CVE-2018-4324",
    "CVE-2018-4326",
    "CVE-2018-4331",
    "CVE-2018-4332",
    "CVE-2018-4333",
    "CVE-2018-4334",
    "CVE-2018-4336",
    "CVE-2018-4337",
    "CVE-2018-4338",
    "CVE-2018-4340",
    "CVE-2018-4341",
    "CVE-2018-4343",
    "CVE-2018-4344",
    "CVE-2018-4346",
    "CVE-2018-4347",
    "CVE-2018-4348",
    "CVE-2018-4350",
    "CVE-2018-4351",
    "CVE-2018-4353",
    "CVE-2018-4354",
    "CVE-2018-4355",
    "CVE-2018-4383",
    "CVE-2018-4393",
    "CVE-2018-4395",
    "CVE-2018-4396",
    "CVE-2018-4399",
    "CVE-2018-4401",
    "CVE-2018-4406",
    "CVE-2018-4407",
    "CVE-2018-4408",
    "CVE-2018-4411",
    "CVE-2018-4412",
    "CVE-2018-4414",
    "CVE-2018-4417",
    "CVE-2018-4418",
    "CVE-2018-4425",
    "CVE-2018-4426",
    "CVE-2018-5383"
  );
  script_bugtraq_id(85054, 104879);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2018-09-24-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/18");

  script_name(english:"macOS < 10.14 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple security
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X that is prior to
10.13.6 or is not macOS 10.14. It is, therefore, affected by multiple
vulnerabilities in the following components :

  - afpserver
  - AppleGraphicsControl
  - Application Firewall
  - App Store
  - APR
  - ATS
  - Auto Unlock
  - Bluetooth
  - CFNetwork
  - CoreFoundation
  - CoreText
  - Crash Reporter
  - CUPS
  - Dictionary
  - Grand Central Dispatch
  - Heimdal
  - Hypervisor
  - iBooks
  - Intel Graphics Driver
  - IOHIDFamily
  - IOKit
  - IOUserEthernet
  - Kernel
  - LibreSSL
  - Login Window
  - mDNSOffloadUserClient
  - MediaRemote
  - Microcode
  - Security
  - Spotlight
  - Symptom Framework
  - Text
  - Wi-Fi

Note that successful exploitation of the most serious issues can
result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT209139");
  # https://lists.apple.com/archives/security-announce/2018/Sep/msg00000.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?27448e16");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS version 10.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-4332");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-4310");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/OS");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

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
if (isnull(matches)) exit(1, "Failed to parse the macOS / Mac OS X version ('" + os + "').");

version = matches[1];
fixed_version = "10.14";

# Patches exist for macOS Sierra 10.12.6, macOS High Sierra 10.13.6
# https://support.apple.com/en-us/HT209193
# Do not mark at or above 10.12.6 and  10.13.6
if (
  # No 10.12.x patch below 10.12.6
  (
    version =~"^10\.12($|[^0-9])"
    &&
    ver_compare(ver:version, fix:'10.12.6', strict:FALSE) == -1
  )
  ||
  # No 10.13.x patch below 10.13.6
  (
    version =~"^10\.13($|[^0-9])"
    &&
    ver_compare(ver:version, fix:'10.13.6', strict:FALSE) == -1
  )
)
{
  security_report_v4(
    port:0,
    severity:SECURITY_HOLE,
    extra:
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version +
      '\n'
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "macOS / Mac OS X", version);
