##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4659-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143429);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2020-0423",
    "CVE-2020-4788",
    "CVE-2020-10135",
    "CVE-2020-14351",
    "CVE-2020-25705",
    "CVE-2020-27152",
    "CVE-2020-28915"
  );
  script_xref(name:"USN", value:"4659-1");
  script_xref(name:"CEA-ID", value:"CEA-2020-0138");

  script_name(english:"Ubuntu 20.10 : Linux kernel vulnerabilities (USN-4659-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
USN-4659-1 advisory.

  - In binder_release_work of binder.c, there is a possible use-after-free due to improper locking. This could
    lead to local escalation of privilege in the kernel with no additional execution privileges needed. User
    interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-161151868References: N/A (CVE-2020-0423)

  - IBM Power9 (AIX 7.1, 7.2, and VIOS 3.1) processors could allow a local user to obtain sensitive
    information from the data in the L1 cache under extenuating circumstances. IBM X-Force ID: 189296.
    (CVE-2020-4788)

  - Legacy pairing and secure-connections pairing authentication in Bluetooth BR/EDR Core Specification v5.2
    and earlier may allow an unauthenticated user to complete authentication without pairing credentials via
    adjacent access. An unauthenticated, adjacent attacker could impersonate a Bluetooth BR/EDR master or
    slave to pair with a previously paired remote device to successfully complete the authentication procedure
    without knowing the link key. (CVE-2020-10135)

  - A flaw in the way reply ICMP packets are limited in the Linux kernel functionality was found that allows
    to quickly scan open UDP ports. This flaw allows an off-path remote user to effectively bypassing source
    port UDP randomization. The highest threat from this vulnerability is to confidentiality and possibly
    integrity, because software that relies on UDP source port randomization are indirectly affected as well.
    Kernel versions before 5.10 may be vulnerable to this issue. (CVE-2020-25705)

  - An issue was discovered in ioapic_lazy_update_eoi in arch/x86/kvm/ioapic.c in the Linux kernel before
    5.9.2. It has an infinite loop related to improper interaction between a resampler and edge triggering,
    aka CID-77377064c3a9. (CVE-2020-27152)

  - A buffer over-read (at the framebuffer layer) in the fbcon code in the Linux kernel before 5.8.15 could be
    used by local attackers to read kernel memory, aka CID-6735b4632def. (CVE-2020-28915)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4659-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0423");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-1008-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-1008-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-1011-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-1011-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-1012-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-1013-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-1014-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-31-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-31-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-31-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-31-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-64k-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-64k-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-20.04-edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2020-2023 Canonical, Inc. / NASL script (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('ksplice.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(20\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  cve_list = make_list('CVE-2020-0423', 'CVE-2020-4788', 'CVE-2020-10135', 'CVE-2020-14351', 'CVE-2020-25705', 'CVE-2020-27152', 'CVE-2020-28915');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-4659-1');
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

pkgs = [
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-1008-raspi', 'pkgver': '5.8.0-1008.11'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-1008-raspi-nolpae', 'pkgver': '5.8.0-1008.11'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-1011-kvm', 'pkgver': '5.8.0-1011.12'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-1011-oracle', 'pkgver': '5.8.0-1011.11'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-1012-gcp', 'pkgver': '5.8.0-1012.12'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-1013-azure', 'pkgver': '5.8.0-1013.14'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-1014-aws', 'pkgver': '5.8.0-1014.15'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-31-generic', 'pkgver': '5.8.0-31.33'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-31-generic-64k', 'pkgver': '5.8.0-31.33'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-31-generic-lpae', 'pkgver': '5.8.0-31.33'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-31-lowlatency', 'pkgver': '5.8.0-31.33'},
    {'osver': '20.10', 'pkgname': 'linux-image-aws', 'pkgver': '5.8.0.1014.16'},
    {'osver': '20.10', 'pkgname': 'linux-image-azure', 'pkgver': '5.8.0.1013.13'},
    {'osver': '20.10', 'pkgname': 'linux-image-gcp', 'pkgver': '5.8.0.1012.12'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic', 'pkgver': '5.8.0.31.36'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic-64k', 'pkgver': '5.8.0.31.36'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic-64k-hwe-20.04', 'pkgver': '5.8.0.31.36'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic-64k-hwe-20.04-edge', 'pkgver': '5.8.0.31.36'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic-hwe-20.04', 'pkgver': '5.8.0.31.36'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic-hwe-20.04-edge', 'pkgver': '5.8.0.31.36'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic-lpae', 'pkgver': '5.8.0.31.36'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic-lpae-hwe-20.04', 'pkgver': '5.8.0.31.36'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic-lpae-hwe-20.04-edge', 'pkgver': '5.8.0.31.36'},
    {'osver': '20.10', 'pkgname': 'linux-image-gke', 'pkgver': '5.8.0.1012.12'},
    {'osver': '20.10', 'pkgname': 'linux-image-kvm', 'pkgver': '5.8.0.1011.12'},
    {'osver': '20.10', 'pkgname': 'linux-image-lowlatency', 'pkgver': '5.8.0.31.36'},
    {'osver': '20.10', 'pkgname': 'linux-image-lowlatency-hwe-20.04', 'pkgver': '5.8.0.31.36'},
    {'osver': '20.10', 'pkgname': 'linux-image-lowlatency-hwe-20.04-edge', 'pkgver': '5.8.0.31.36'},
    {'osver': '20.10', 'pkgname': 'linux-image-oem-20.04', 'pkgver': '5.8.0.31.36'},
    {'osver': '20.10', 'pkgname': 'linux-image-oracle', 'pkgver': '5.8.0.1011.11'},
    {'osver': '20.10', 'pkgname': 'linux-image-raspi', 'pkgver': '5.8.0.1008.11'},
    {'osver': '20.10', 'pkgname': 'linux-image-raspi-nolpae', 'pkgver': '5.8.0.1008.11'},
    {'osver': '20.10', 'pkgname': 'linux-image-virtual', 'pkgver': '5.8.0.31.36'},
    {'osver': '20.10', 'pkgname': 'linux-image-virtual-hwe-20.04', 'pkgver': '5.8.0.31.36'},
    {'osver': '20.10', 'pkgname': 'linux-image-virtual-hwe-20.04-edge', 'pkgver': '5.8.0.31.36'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-image-5.8.0-1008-raspi / linux-image-5.8.0-1008-raspi-nolpae / etc');
}