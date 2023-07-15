#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4992-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150867);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2020-14372",
    "CVE-2020-25632",
    "CVE-2020-27749",
    "CVE-2020-27779",
    "CVE-2021-20225",
    "CVE-2021-20233"
  );
  script_xref(name:"USN", value:"4992-1");
  script_xref(name:"IAVA", value:"2020-A-0349");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : GRUB 2 vulnerabilities (USN-4992-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-4992-1 advisory.

  - A flaw was found in grub2 in versions prior to 2.06, where it incorrectly enables the usage of the ACPI
    command when Secure Boot is enabled. This flaw allows an attacker with privileged access to craft a
    Secondary System Description Table (SSDT) containing code to overwrite the Linux kernel lockdown variable
    content directly into memory. The table is further loaded and executed by the kernel, defeating its Secure
    Boot lockdown and allowing the attacker to load unsigned code. The highest threat from this vulnerability
    is to data confidentiality and integrity, as well as system availability. (CVE-2020-14372)

  - A flaw was found in grub2 in versions prior to 2.06. The rmmod implementation allows the unloading of a
    module used as a dependency without checking if any other dependent module is still loaded leading to a
    use-after-free scenario. This could allow arbitrary code to be executed or a bypass of Secure Boot
    protections. The highest threat from this vulnerability is to data confidentiality and integrity as well
    as system availability. (CVE-2020-25632)

  - A flaw was found in grub2 in versions prior to 2.06. Variable names present are expanded in the supplied
    command line into their corresponding variable contents, using a 1kB stack buffer for temporary storage,
    without sufficient bounds checking. If the function is called with a command line that references a
    variable with a sufficiently large payload, it is possible to overflow the stack buffer, corrupt the stack
    frame and control execution which could also circumvent Secure Boot protections. The highest threat from
    this vulnerability is to data confidentiality and integrity as well as system availability.
    (CVE-2020-27749)

  - A flaw was found in grub2 in versions prior to 2.06. The cutmem command does not honor secure boot locking
    allowing an privileged attacker to remove address ranges from memory creating an opportunity to circumvent
    SecureBoot protections after proper triage about grub's memory layout. The highest threat from this
    vulnerability is to data confidentiality and integrity as well as system availability. (CVE-2020-27779)

  - A flaw was found in grub2 in versions prior to 2.06. The option parser allows an attacker to write past
    the end of a heap-allocated buffer by calling certain commands with a large number of specific short forms
    of options. The highest threat from this vulnerability is to data confidentiality and integrity as well as
    system availability. (CVE-2021-20225)

  - A flaw was found in grub2 in versions prior to 2.06. Setparam_prefix() in the menu rendering code performs
    a length calculation on the assumption that expressing a quoted single quote will require 3 characters,
    while it actually requires 4 characters which allows an attacker to corrupt memory by one byte for each
    quote in the input. The highest threat from this vulnerability is to data confidentiality and integrity as
    well as system availability. (CVE-2021-20233)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4992-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20233");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-amd64-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-amd64-signed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-arm64-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-arm64-signed");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(18\.04|20\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '18.04', 'pkgname': 'grub-efi-amd64', 'pkgver': '2.04-1ubuntu44.1.2'},
    {'osver': '18.04', 'pkgname': 'grub-efi-amd64-bin', 'pkgver': '2.04-1ubuntu44.1.2'},
    {'osver': '18.04', 'pkgname': 'grub-efi-amd64-signed', 'pkgver': '1.167~18.04.5+2.04-1ubuntu44.1.2'},
    {'osver': '18.04', 'pkgname': 'grub-efi-arm64', 'pkgver': '2.04-1ubuntu44.1.2'},
    {'osver': '18.04', 'pkgname': 'grub-efi-arm64-bin', 'pkgver': '2.04-1ubuntu44.1.2'},
    {'osver': '18.04', 'pkgname': 'grub-efi-arm64-signed', 'pkgver': '1.167~18.04.5+2.04-1ubuntu44.1.2'},
    {'osver': '20.04', 'pkgname': 'grub-efi-amd64', 'pkgver': '2.04-1ubuntu44.2'},
    {'osver': '20.04', 'pkgname': 'grub-efi-amd64-bin', 'pkgver': '2.04-1ubuntu44.2'},
    {'osver': '20.04', 'pkgname': 'grub-efi-amd64-signed', 'pkgver': '1.167.2+2.04-1ubuntu44.2'},
    {'osver': '20.04', 'pkgname': 'grub-efi-arm64', 'pkgver': '2.04-1ubuntu44.2'},
    {'osver': '20.04', 'pkgname': 'grub-efi-arm64-bin', 'pkgver': '2.04-1ubuntu44.2'},
    {'osver': '20.04', 'pkgname': 'grub-efi-arm64-signed', 'pkgver': '1.167.2+2.04-1ubuntu44.2'}
];

flag = 0;
foreach package_array ( pkgs ) {
  osver = NULL;
  pkgname = NULL;
  pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'grub-efi-amd64 / grub-efi-amd64-bin / grub-efi-amd64-signed / etc');
}
