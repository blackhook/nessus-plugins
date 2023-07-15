#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4349-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(136282);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2018-12178", "CVE-2018-12180", "CVE-2018-12181", "CVE-2019-14558", "CVE-2019-14559", "CVE-2019-14563", "CVE-2019-14575", "CVE-2019-14586", "CVE-2019-14587");
  script_xref(name:"USN", value:"4349-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 19.10 : EDK II vulnerabilities (USN-4349-1)");
  script_summary(english:"Checks dpkg output for updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Ubuntu host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A buffer overflow was discovered in the network stack. An unprivileged
user could potentially enable escalation of privilege and/or denial of
service. This issue was already fixed in a previous release for 18.04
LTS and 19.10. (CVE-2018-12178)

A buffer overflow was discovered in BlockIo service. An
unauthenticated user could potentially enable escalation of privilege,
information disclosure and/or denial of service. This issue was
already fixed in a previous release for 18.04 LTS and 19.10.
(CVE-2018-12180)

A stack overflow was discovered in bmp. An unprivileged user could
potentially enable denial of service or elevation of privilege via
local access. This issue was already fixed in a previous release for
18.04 LTS and 19.10. (CVE-2018-12181)

It was discovered that memory was not cleared before free that could
lead to potential password leak. (CVE-2019-14558)

A memory leak was discovered in ArpOnFrameRcvdDpc. An attacker could
possibly use this issue to cause a denial of service or other
unspecified impact. (CVE-2019-14559)

An integer overflow was discovered in
MdeModulePkg/PiDxeS3BootScriptLib. An attacker could possibly use this
issue to cause a denial of service or other unspecified impact.
(CVE-2019-14563)

It was discovered that the affected version doesn't properly check
whether an unsigned EFI file should be allowed or not. An attacker
could possibly load unsafe content by bypassing the verification.
(CVE-2019-14575)

It was discovered that original configuration runtime memory is freed,
but it is still exposed to the OS runtime. (CVE-2019-14586)

A double-unmap was discovered in TRB creation. An attacker could use
it to cause a denial of service or other unspecified impact.
(CVE-2019-14587).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4349-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12180");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ovmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-efi-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-efi-arm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2020-2023 Canonical, Inc. / NASL script (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! preg(pattern:"^(16\.04|18\.04|19\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04 / 18.04 / 19.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"ovmf", pkgver:"0~20160408.ffea0a2c-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-efi", pkgver:"0~20160408.ffea0a2c-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"ovmf", pkgver:"0~20180205.c0d9813c-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"qemu-efi-aarch64", pkgver:"0~20180205.c0d9813c-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"qemu-efi-arm", pkgver:"0~20180205.c0d9813c-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"ovmf", pkgver:"0~20190606.20d2e5a1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"qemu-efi-aarch64", pkgver:"0~20190606.20d2e5a1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"qemu-efi-arm", pkgver:"0~20190606.20d2e5a1-2ubuntu1.1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ovmf / qemu-efi / qemu-efi-aarch64 / qemu-efi-arm");
}
