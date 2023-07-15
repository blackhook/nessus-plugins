#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134954);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id(
    "CVE-2019-8853",
    "CVE-2019-14615",
    "CVE-2019-19232",
    "CVE-2020-3851",
    "CVE-2020-3881",
    "CVE-2020-3883",
    "CVE-2020-3884",
    "CVE-2020-3889",
    "CVE-2020-3892",
    "CVE-2020-3893",
    "CVE-2020-3898",
    "CVE-2020-3903",
    "CVE-2020-3904",
    "CVE-2020-3905",
    "CVE-2020-3906",
    "CVE-2020-3907",
    "CVE-2020-3908",
    "CVE-2020-3909",
    "CVE-2020-3910",
    "CVE-2020-3911",
    "CVE-2020-3912",
    "CVE-2020-3913",
    "CVE-2020-3914",
    "CVE-2020-3915",
    "CVE-2020-3918",
    "CVE-2020-3919",
    "CVE-2020-9769",
    "CVE-2020-9773",
    "CVE-2020-9776",
    "CVE-2020-9785",
    "CVE-2020-9786",
    "CVE-2020-9787"
  );
  script_xref(name:"APPLE-SA", value:"HT211100");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2020-03-20");
  script_xref(name:"IAVA", value:"2020-A-0120-S");

  script_name(english:"macOS 10.15.x < 10.15.4 / 10.14.x < 10.14.6 Security Update 2020-002 / 10.13.x < 10.13.6 Security Update 2020-002");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 10.13.x prior to 10.13.6 Security Update 2020-002,
10.14.x prior to 10.14.6 Security Update 2020-002, or 10.15.x prior to 10.15.4. It is, therefore, affected by multiple
vulnerabilities :

  - Insufficient control flow in certain data structures for some Intel(R) Processors with Intel(R) Processor
    Graphics may allow an unauthenticated user to potentially enable information disclosure via local access.
    (CVE-2019-14615)

  - ** DISPUTED ** In Sudo through 1.8.29, an attacker with access to a Runas ALL sudoer account can
    impersonate a nonexistent user by invoking sudo with a numeric uid that is not associated with any user.
    NOTE: The software maintainer believes that this is not a vulnerability because running a command via sudo
    as a user not present in the local password database is an intentional feature. Because this behavior
    surprised some users, sudo 1.8.30 introduced an option to enable/disable this behavior with the default
    being disabled. However, this does not change the fact that sudo was behaving as intended, and as
    documented, in earlier versions. (CVE-2019-19232)

  - An out-of-bounds read error exists in Bluetooth due to improper input sanitization. An attacker can
    exploit this to read restricted memory. (CVE-2019-8853)

  - Privilege escalation vulnerabilities exist in IOThunderboltFamily (due to a use-after-free flaw), and in
    CUPS (due to a memory corruption issue). An attacker can exploit this to gain elevated access to the 
    system. (CVE-2020-3851, CVE-2020-3898)

  - An information disclosure vulnerability exists in FaceTime, Icons, and Call History. An unauthenticated,
    local attacker can exploit this, via malicious applications, to disclose potentially sensitive
    information. (CVE-2020-3881, CVE-2020-9773, CVE-2020-9776)

  - An information disclosure vulnerability exists in Sandbox. A local user can exploit this to view
    sensitvie user information. (CVE-2020-3918)

  - An unspecified issue exists in AppleMobileFileIntegrity due to an unspecified reason. An attacker can
    exploit this to use arbitrary entitlements. (CVE-2020-3883)

  - An arbitrary code execution vulnerability exists in Mail due to improper input validation. An
    unauthenticated, remote attacker can exploit this to bypass authentication and execute arbitrary
    JavaScript code. (CVE-2020-3884)

  - An arbitrary file read vulnerability exists in Time Machine due to improper state management. An
    unauthenticated, local attacker can exploit this to read arbitrary files and disclose sensitive
    information. (CVE-2020-3889)

  - An arbitrary code execution vulnerability exists in AppleGraphicsControl, Bluetooth, IOHIDFamily, and the
    kernel due to memory initialization and corruption issues. An attacker can exploit this to bypass
    authentication and execute arbitrary commands with kernel privileges. (CVE-2020-3892, CVE-2020-3893,
    CVE-2020-3904, CVE-2020-3905, CVE-2020-3919, CVE-2020-9785)

  - An arbitrary code execution vulnerability exists in Apple HSSPI Support due to a memory corruption issue.
    An attacker can exploit this to bypass authentication and execute arbitrary commands with system
    privileges. (CVE-2020-3903)

  - A logic issue exists in TCC due to an unspecified reason. An attacker can exploit this, via a maliciously
    crafted application, to cause bypass code signing. (CVE-2020-3906)

  - An out-of-bounds read error exists in Bluetooth due to improper input validation. An unauthenticated local
    attacker can exploit this to cause a denial of service or read kernel memory. (CVE-2020-3907,
    CVE-2020-3908, CVE-2020-3912)

  - A buffer overflow condition exists in libxml2 due to improper bounds checking and size validation. An
    attacker can exploit this to cause a denial of service condition or the execution of arbitrary code.
    (CVE-2020-3909, CVE-2020-3910, CVE-2020-3911)

  - A privilege escalation vulnerability exists in due to improper permission validation. An unauthenticated,
    remote attacker can exploit this, to gain elevated access to the system. (CVE-2020-3913)

  - An information disclosure vulnerability exists in the kernel due to improper memory handling. An attacker
    can exploit this to read restricted memory. (CVE-2020-3914)

  - An arbitrary file overwrite vulnerability exists in Printing due improper path handlng. An attacker can 
    exploit this to overwrite arbitrary files. (CVE-2020-3915)

  - Multiple unspecified issues exist in the Vim installation on macOS. An attacker can exploit this to cause
    an unknown impact. (CVE-2020-9769)

  - An unspecified vulnerability exists in sysdiagnose due to insufficient validation of user supplied input. 
    An attacker could exploit this issue with partial impact on the confidentiality, integrity & availability
    of the application and/or system. (CVE-2020-9786)

  - An vulnerability exists in WebKit due to a logic flaw in restrictions. An attacker may exploit this flaw,
    as part of a more elaborate attack, to gain unauthorized access to the MacOS camera. (CVE-2020-9787)

Note that Nessus has not tested for this issue but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT211100");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 10.15.4 / 10.14.x < 10.14.6 Security Update 2020-002 / 10.13.x < 10.13.6 Security Update 2020-002 or
later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9785");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-9769");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/OS");

  exit(0);
}

include('vcf.inc');
include('lists.inc');
include('vcf_extras_apple.inc');

app_info = vcf::apple::macos::get_app_info();

constraints = [
  { 'max_version' : '10.13.6', 'min_version' : '10.13', 'fixed_build' : '17G12034', 'fixed_display' : '10.13.6 Security Update 2020-002' },
  { 'max_version' : '10.14.6', 'min_version' : '10.14', 'fixed_build' : '18G4032', 'fixed_display' : '10.14.6 Security Update 2020-002' },
  { 'max_version' : '10.15.3', 'min_version' : '10.15', 'fixed_version' : '10.15.4', 'fixed_display' : 'macOS Catalina 10.15.4' }
];

vcf::apple::macos::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
