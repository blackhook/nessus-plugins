#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(118575);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/16");

  script_cve_id(
    "CVE-2017-12613",
    "CVE-2017-12618",
    "CVE-2018-3639",
    "CVE-2018-3640",
    "CVE-2018-3646",
    "CVE-2018-4126",
    "CVE-2018-4153",
    "CVE-2018-4203",
    "CVE-2018-4295",
    "CVE-2018-4304",
    "CVE-2018-4308",
    "CVE-2018-4310",
    "CVE-2018-4326",
    "CVE-2018-4331",
    "CVE-2018-4340",
    "CVE-2018-4341",
    "CVE-2018-4342",
    "CVE-2018-4346",
    "CVE-2018-4348",
    "CVE-2018-4350",
    "CVE-2018-4354",
    "CVE-2018-4368",
    "CVE-2018-4369",
    "CVE-2018-4371",
    "CVE-2018-4393",
    "CVE-2018-4394",
    "CVE-2018-4395",
    "CVE-2018-4396",
    "CVE-2018-4398",
    "CVE-2018-4399",
    "CVE-2018-4400",
    "CVE-2018-4401",
    "CVE-2018-4402",
    "CVE-2018-4406",
    "CVE-2018-4407",
    "CVE-2018-4408",
    "CVE-2018-4410",
    "CVE-2018-4411",
    "CVE-2018-4412",
    "CVE-2018-4413",
    "CVE-2018-4415",
    "CVE-2018-4417",
    "CVE-2018-4418",
    "CVE-2018-4419",
    "CVE-2018-4420",
    "CVE-2018-4422",
    "CVE-2018-4423",
    "CVE-2018-4425",
    "CVE-2018-4426"
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2018-10-30-2");
  script_xref(name:"IAVA", value:"2021-A-0356-S");

  script_name(english:"macOS 10.13.6 Multiple Vulnerabilities (Security Update 2018-002)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS security update that fixes
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running macOS 10.13.6 and is missing a security
update. It is therefore, affected by multiple vulnerabilities
affecting the following components :

  - fpserver
  - AppleGraphicsControl
  - APR
  - ATS
  - CFNetwork
  - CoreAnimation
  - CoreCrypto
  - CoreFoundation
  - CUPS
  - Dictionary
  - dyld
  - EFI
  - Foundation
  - Grand Central Dispatch
  - Heimdal
  - Hypervisor
  - ICU
  - Intel Graphics Driver
  - IOGraphics
  - IOHIDFamily
  - IOKit
  - IOUserEthernet
  - IPSec
  - Kernel
  - Login Window
  - mDNSOffloadUserClient
  - MediaRemote
  - Microcode
  - NetworkExtension
  - Security
  - Spotlight
  - Symptom Framework
  - WiFi");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT209193");
  # https://lists.apple.com/archives/security-announce/2018/Oct/msg00003.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f0681c90");
  script_set_attribute(attribute:"solution", value:
"Install Security Update 2018-002 or later for 10.13.6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-4331");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-4310");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "Host/MacOSX/packages/boms");

  exit(0);
}
include('lists.inc');
include('vcf.inc');
include('vcf_extras_apple.inc');

app_info = vcf::apple::macos::get_app_info();

constraints = [
  { 'min_version' : '10.13', 'max_version' : '10.13.6', 'fixed_build': '17G3025', 'fixed_display' : '10.13.6 Security Update 2018-002' }
];

vcf::apple::macos::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
