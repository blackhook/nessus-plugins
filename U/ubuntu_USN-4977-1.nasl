#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4977-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(150151);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2020-25670",
    "CVE-2020-25671",
    "CVE-2020-25672",
    "CVE-2020-25673",
    "CVE-2021-3501",
    "CVE-2021-29155"
  );
  script_xref(name:"USN", value:"4977-1");

  script_name(english:"Ubuntu 21.04 : Linux kernel vulnerabilities (USN-4977-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 21.04 host has packages installed that are affected by multiple vulnerabilities as referenced in the
USN-4977-1 advisory.

  - A vulnerability was found in Linux Kernel where refcount leak in llcp_sock_bind() causing use-after-free
    which might lead to privilege escalations. (CVE-2020-25670)

  - A vulnerability was found in Linux Kernel, where a refcount leak in llcp_sock_connect() causing use-after-
    free which might lead to privilege escalations. (CVE-2020-25671)

  - A memory leak vulnerability was found in Linux kernel in llcp_sock_connect (CVE-2020-25672)

  - A vulnerability was found in Linux kernel where non-blocking socket in llcp_sock_connect() leads to leak
    and eventually hanging-up the system. (CVE-2020-25673)

  - A flaw was found in the Linux kernel in versions before 5.12. The value of internal.ndata, in the KVM API,
    is mapped to an array index, which can be updated by a user process at anytime which could lead to an out-
    of-bounds write. The highest threat from this vulnerability is to data integrity and system availability.
    (CVE-2021-3501)

  - An issue was discovered in the Linux kernel through 5.11.x. kernel/bpf/verifier.c performs undesirable
    out-of-bounds speculation on pointer arithmetic, leading to side-channel attacks that defeat Spectre
    mitigations and obtain sensitive information from kernel memory. Specifically, for sequences of pointer
    arithmetic operations, the pointer modification performed by the first operation is not correctly
    accounted for when restricting subsequent operations. (CVE-2021-29155)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4977-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25671");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-1006-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-1007-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-1008-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-1008-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-1008-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-18-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-18-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-18-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-18-lowlatency");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-20.04-edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(21\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 21.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  cve_list = make_list('CVE-2020-25670', 'CVE-2020-25671', 'CVE-2020-25672', 'CVE-2020-25673', 'CVE-2021-3501', 'CVE-2021-29155');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-4977-1');
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

pkgs = [
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-1006-azure', 'pkgver': '5.11.0-1006.6'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-1007-oracle', 'pkgver': '5.11.0-1007.7'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-1008-aws', 'pkgver': '5.11.0-1008.8'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-1008-gcp', 'pkgver': '5.11.0-1008.9'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-1008-kvm', 'pkgver': '5.11.0-1008.8'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-18-generic', 'pkgver': '5.11.0-18.19'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-18-generic-64k', 'pkgver': '5.11.0-18.19'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-18-generic-lpae', 'pkgver': '5.11.0-18.19'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-18-lowlatency', 'pkgver': '5.11.0-18.19'},
    {'osver': '21.04', 'pkgname': 'linux-image-aws', 'pkgver': '5.11.0.1008.8'},
    {'osver': '21.04', 'pkgname': 'linux-image-azure', 'pkgver': '5.11.0.1006.6'},
    {'osver': '21.04', 'pkgname': 'linux-image-gcp', 'pkgver': '5.11.0.1008.8'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic', 'pkgver': '5.11.0.18.19'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-64k', 'pkgver': '5.11.0.18.19'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-64k-hwe-20.04', 'pkgver': '5.11.0.18.19'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-64k-hwe-20.04-edge', 'pkgver': '5.11.0.18.19'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-hwe-20.04', 'pkgver': '5.11.0.18.19'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-hwe-20.04-edge', 'pkgver': '5.11.0.18.19'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-lpae', 'pkgver': '5.11.0.18.19'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-lpae-hwe-20.04', 'pkgver': '5.11.0.18.19'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-lpae-hwe-20.04-edge', 'pkgver': '5.11.0.18.19'},
    {'osver': '21.04', 'pkgname': 'linux-image-gke', 'pkgver': '5.11.0.1008.8'},
    {'osver': '21.04', 'pkgname': 'linux-image-kvm', 'pkgver': '5.11.0.1008.8'},
    {'osver': '21.04', 'pkgname': 'linux-image-lowlatency', 'pkgver': '5.11.0.18.19'},
    {'osver': '21.04', 'pkgname': 'linux-image-lowlatency-hwe-20.04', 'pkgver': '5.11.0.18.19'},
    {'osver': '21.04', 'pkgname': 'linux-image-lowlatency-hwe-20.04-edge', 'pkgver': '5.11.0.18.19'},
    {'osver': '21.04', 'pkgname': 'linux-image-oem-20.04', 'pkgver': '5.11.0.18.19'},
    {'osver': '21.04', 'pkgname': 'linux-image-oracle', 'pkgver': '5.11.0.1007.7'},
    {'osver': '21.04', 'pkgname': 'linux-image-virtual', 'pkgver': '5.11.0.18.19'},
    {'osver': '21.04', 'pkgname': 'linux-image-virtual-hwe-20.04', 'pkgver': '5.11.0.18.19'},
    {'osver': '21.04', 'pkgname': 'linux-image-virtual-hwe-20.04-edge', 'pkgver': '5.11.0.18.19'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-image-5.11.0-1006-azure / linux-image-5.11.0-1007-oracle / etc');
}