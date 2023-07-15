#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5137-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155222);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2019-19449",
    "CVE-2020-36385",
    "CVE-2021-3428",
    "CVE-2021-3739",
    "CVE-2021-3743",
    "CVE-2021-3753",
    "CVE-2021-3759",
    "CVE-2021-34556",
    "CVE-2021-35477"
  );
  script_xref(name:"USN", value:"5137-2");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : Linux kernel vulnerabilities (USN-5137-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-5137-2 advisory.

  - An issue was discovered in the Linux kernel before 5.10. drivers/infiniband/core/ucma.c has a use-after-
    free because the ctx is reached via the ctx_list in some ucma_migrate_id situations where ucma_close is
    called, aka CID-f5449e74802c. (CVE-2020-36385)

  - In the Linux kernel 5.0.21, mounting a crafted f2fs filesystem image can lead to slab-out-of-bounds read
    access in f2fs_build_segment_manager in fs/f2fs/segment.c, related to init_min_max_mtime in
    fs/f2fs/segment.c (because the second argument to get_seg_entry is not validated). (CVE-2019-19449)

  - A race problem was seen in the vt_k_ioctl in drivers/tty/vt/vt_ioctl.c in the Linux kernel, which may
    cause an out of bounds read in vt as the write access to vc_mode is not protected by lock-in vt_ioctl
    (KDSETMDE). The highest threat from this vulnerability is to data confidentiality. (CVE-2021-3753)

  - In the Linux kernel through 5.13.7, an unprivileged BPF program can obtain sensitive information from
    kernel memory via a Speculative Store Bypass side-channel attack because the protection mechanism neglects
    the possibility of uninitialized memory locations on the BPF stack. (CVE-2021-34556)

  - In the Linux kernel through 5.13.7, an unprivileged BPF program can obtain sensitive information from
    kernel memory via a Speculative Store Bypass side-channel attack because a certain preempting store
    operation does not necessarily occur before a store operation that has an attacker-controlled value.
    (CVE-2021-35477)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5137-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-36385");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-bluefield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-bluefield-headers-5.4.0-1021");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-bluefield-tools-5.4.0-1021");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1021-bluefield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1055-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1057-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gke-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gke-5.4-headers-5.4.0-1055");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gke-5.4-tools-5.4.0-1055");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1021-bluefield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1055-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1057-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-bluefield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gke-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1021-bluefield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1055-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1057-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-bluefield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1021-bluefield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1055-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1057-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1021-bluefield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1055-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1057-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-1055-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-1057-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gke-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-5.4-headers-5.4.0-1057");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-5.4-tools-5.4.0-1057");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-headers-5.4.0-1057");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-tools-5.4.0-1057");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1021-bluefield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1055-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1057-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-bluefield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gke-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oracle-lts-20.04");
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
var release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
var release = chomp(release);
if (! preg(pattern:"^(18\.04|20\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2019-19449', 'CVE-2020-36385', 'CVE-2021-3428', 'CVE-2021-3739', 'CVE-2021-3743', 'CVE-2021-3753', 'CVE-2021-3759', 'CVE-2021-34556', 'CVE-2021-35477');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5137-2');
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var pkgs = [
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1055-gke', 'pkgver': '5.4.0-1055.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1057-oracle', 'pkgver': '5.4.0-1057.61~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-gke-5.4', 'pkgver': '5.4.0.1055.58~18.04.20'},
    {'osver': '18.04', 'pkgname': 'linux-gke-5.4-headers-5.4.0-1055', 'pkgver': '5.4.0-1055.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-gke-5.4-tools-5.4.0-1055', 'pkgver': '5.4.0-1055.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1055-gke', 'pkgver': '5.4.0-1055.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1057-oracle', 'pkgver': '5.4.0-1057.61~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-gke-5.4', 'pkgver': '5.4.0.1055.58~18.04.20'},
    {'osver': '18.04', 'pkgname': 'linux-headers-oracle', 'pkgver': '5.4.0.1057.61~18.04.37'},
    {'osver': '18.04', 'pkgname': 'linux-headers-oracle-edge', 'pkgver': '5.4.0.1057.61~18.04.37'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1055-gke', 'pkgver': '5.4.0-1055.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1057-oracle', 'pkgver': '5.4.0-1057.61~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-gke-5.4', 'pkgver': '5.4.0.1055.58~18.04.20'},
    {'osver': '18.04', 'pkgname': 'linux-image-oracle', 'pkgver': '5.4.0.1057.61~18.04.37'},
    {'osver': '18.04', 'pkgname': 'linux-image-oracle-edge', 'pkgver': '5.4.0.1057.61~18.04.37'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-1055-gke', 'pkgver': '5.4.0-1055.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-1057-oracle', 'pkgver': '5.4.0-1057.61~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1055-gke', 'pkgver': '5.4.0-1055.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1057-oracle', 'pkgver': '5.4.0-1057.61~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-1055-gke', 'pkgver': '5.4.0-1055.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-1057-oracle', 'pkgver': '5.4.0-1057.61~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-gke-5.4', 'pkgver': '5.4.0.1055.58~18.04.20'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-oracle', 'pkgver': '5.4.0.1057.61~18.04.37'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-oracle-edge', 'pkgver': '5.4.0.1057.61~18.04.37'},
    {'osver': '18.04', 'pkgname': 'linux-oracle', 'pkgver': '5.4.0.1057.61~18.04.37'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-5.4-headers-5.4.0-1057', 'pkgver': '5.4.0-1057.61~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-5.4-tools-5.4.0-1057', 'pkgver': '5.4.0-1057.61~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-edge', 'pkgver': '5.4.0.1057.61~18.04.37'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-oracle', 'pkgver': '5.4.0.1057.61~18.04.37'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-oracle-edge', 'pkgver': '5.4.0.1057.61~18.04.37'},
    {'osver': '18.04', 'pkgname': 'linux-signed-oracle', 'pkgver': '5.4.0.1057.61~18.04.37'},
    {'osver': '18.04', 'pkgname': 'linux-signed-oracle-edge', 'pkgver': '5.4.0.1057.61~18.04.37'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1055-gke', 'pkgver': '5.4.0-1055.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1057-oracle', 'pkgver': '5.4.0-1057.61~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-gke-5.4', 'pkgver': '5.4.0.1055.58~18.04.20'},
    {'osver': '18.04', 'pkgname': 'linux-tools-oracle', 'pkgver': '5.4.0.1057.61~18.04.37'},
    {'osver': '18.04', 'pkgname': 'linux-tools-oracle-edge', 'pkgver': '5.4.0.1057.61~18.04.37'},
    {'osver': '20.04', 'pkgname': 'linux-bluefield', 'pkgver': '5.4.0.1021.22'},
    {'osver': '20.04', 'pkgname': 'linux-bluefield-headers-5.4.0-1021', 'pkgver': '5.4.0-1021.24'},
    {'osver': '20.04', 'pkgname': 'linux-bluefield-tools-5.4.0-1021', 'pkgver': '5.4.0-1021.24'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1021-bluefield', 'pkgver': '5.4.0-1021.24'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1057-oracle', 'pkgver': '5.4.0-1057.61'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1021-bluefield', 'pkgver': '5.4.0-1021.24'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1057-oracle', 'pkgver': '5.4.0-1057.61'},
    {'osver': '20.04', 'pkgname': 'linux-headers-bluefield', 'pkgver': '5.4.0.1021.22'},
    {'osver': '20.04', 'pkgname': 'linux-headers-oracle-lts-20.04', 'pkgver': '5.4.0.1057.57'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1021-bluefield', 'pkgver': '5.4.0-1021.24'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1057-oracle', 'pkgver': '5.4.0-1057.61'},
    {'osver': '20.04', 'pkgname': 'linux-image-bluefield', 'pkgver': '5.4.0.1021.22'},
    {'osver': '20.04', 'pkgname': 'linux-image-oracle-lts-20.04', 'pkgver': '5.4.0.1057.57'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1021-bluefield', 'pkgver': '5.4.0-1021.24'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1057-oracle', 'pkgver': '5.4.0-1057.61'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1021-bluefield', 'pkgver': '5.4.0-1021.24'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1057-oracle', 'pkgver': '5.4.0-1057.61'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.4.0-1057-oracle', 'pkgver': '5.4.0-1057.61'},
    {'osver': '20.04', 'pkgname': 'linux-oracle-headers-5.4.0-1057', 'pkgver': '5.4.0-1057.61'},
    {'osver': '20.04', 'pkgname': 'linux-oracle-lts-20.04', 'pkgver': '5.4.0.1057.57'},
    {'osver': '20.04', 'pkgname': 'linux-oracle-tools-5.4.0-1057', 'pkgver': '5.4.0-1057.61'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1021-bluefield', 'pkgver': '5.4.0-1021.24'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1057-oracle', 'pkgver': '5.4.0-1057.61'},
    {'osver': '20.04', 'pkgname': 'linux-tools-bluefield', 'pkgver': '5.4.0.1021.22'},
    {'osver': '20.04', 'pkgname': 'linux-tools-oracle-lts-20.04', 'pkgver': '5.4.0.1057.57'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
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
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-bluefield / linux-bluefield-headers-5.4.0-1021 / etc');
}
