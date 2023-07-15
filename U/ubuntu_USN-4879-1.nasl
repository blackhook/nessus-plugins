##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4879-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147974);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2020-36158", "CVE-2021-20194");
  script_xref(name:"USN", value:"4879-1");

  script_name(english:"Ubuntu 20.04 LTS / 20.10 : Linux kernel vulnerabilities (USN-4879-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 20.10 host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-4879-1 advisory.

  - mwifiex_cmd_802_11_ad_hoc_start in drivers/net/wireless/marvell/mwifiex/join.c in the Linux kernel through
    5.10.4 might allow remote attackers to execute arbitrary code via a long SSID value, aka CID-5c455c5ab332.
    (CVE-2020-36158)

  - There is a vulnerability in the linux kernel versions higher than 5.2 (if kernel compiled with config
    params CONFIG_BPF_SYSCALL=y , CONFIG_BPF=y , CONFIG_CGROUPS=y , CONFIG_CGROUP_BPF=y ,
    CONFIG_HARDENED_USERCOPY not set, and BPF hook to getsockopt is registered). As result of BPF execution,
    the local user can trigger bug in __cgroup_bpf_run_filter_getsockopt() function that can lead to heap
    overflow (because of non-hardened usercopy). The impact of attack could be deny of service or possibly
    privileges escalation. (CVE-2021-20194)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4879-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-36158");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-20194");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-1017-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-1017-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-1020-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-1022-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-1024-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-1024-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-1025-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-45-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-45-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-45-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-45-lowlatency");
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
if (! preg(pattern:"^(20\.04|20\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 20.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  cve_list = make_list('CVE-2020-36158', 'CVE-2021-20194');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-4879-1');
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

pkgs = [
    {'osver': '20.04', 'pkgname': 'linux-image-5.8.0-45-generic', 'pkgver': '5.8.0-45.51~20.04.1+1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.8.0-45-generic-64k', 'pkgver': '5.8.0-45.51~20.04.1+1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.8.0-45-generic-lpae', 'pkgver': '5.8.0-45.51~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.8.0-45-lowlatency', 'pkgver': '5.8.0-45.51~20.04.1+1'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-64k-hwe-20.04', 'pkgver': '5.8.0.45.51~20.04.31'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-64k-hwe-20.04-edge', 'pkgver': '5.8.0.45.51~20.04.31'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-hwe-20.04', 'pkgver': '5.8.0.45.51~20.04.31'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-hwe-20.04-edge', 'pkgver': '5.8.0.45.51~20.04.31'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae-hwe-20.04', 'pkgver': '5.8.0.45.51~20.04.31'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae-hwe-20.04-edge', 'pkgver': '5.8.0.45.51~20.04.31'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency-hwe-20.04', 'pkgver': '5.8.0.45.51~20.04.31'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency-hwe-20.04-edge', 'pkgver': '5.8.0.45.51~20.04.31'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual-hwe-20.04', 'pkgver': '5.8.0.45.51~20.04.31'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual-hwe-20.04-edge', 'pkgver': '5.8.0.45.51~20.04.31'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-1017-raspi', 'pkgver': '5.8.0-1017.20'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-1017-raspi-nolpae', 'pkgver': '5.8.0-1017.20'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-1020-kvm', 'pkgver': '5.8.0-1020.22'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-1022-oracle', 'pkgver': '5.8.0-1022.23'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-1024-azure', 'pkgver': '5.8.0-1024.26'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-1024-gcp', 'pkgver': '5.8.0-1024.25'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-1025-aws', 'pkgver': '5.8.0-1025.27'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-45-generic', 'pkgver': '5.8.0-45.51'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-45-generic-64k', 'pkgver': '5.8.0-45.51'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-45-generic-lpae', 'pkgver': '5.8.0-45.51'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-45-lowlatency', 'pkgver': '5.8.0-45.51'},
    {'osver': '20.10', 'pkgname': 'linux-image-aws', 'pkgver': '5.8.0.1025.27'},
    {'osver': '20.10', 'pkgname': 'linux-image-azure', 'pkgver': '5.8.0.1024.24'},
    {'osver': '20.10', 'pkgname': 'linux-image-gcp', 'pkgver': '5.8.0.1024.24'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic', 'pkgver': '5.8.0.45.50'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic-64k', 'pkgver': '5.8.0.45.50'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic-64k-hwe-20.04', 'pkgver': '5.8.0.45.50'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic-64k-hwe-20.04-edge', 'pkgver': '5.8.0.45.50'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic-hwe-20.04', 'pkgver': '5.8.0.45.50'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic-hwe-20.04-edge', 'pkgver': '5.8.0.45.50'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic-lpae', 'pkgver': '5.8.0.45.50'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic-lpae-hwe-20.04', 'pkgver': '5.8.0.45.50'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic-lpae-hwe-20.04-edge', 'pkgver': '5.8.0.45.50'},
    {'osver': '20.10', 'pkgname': 'linux-image-gke', 'pkgver': '5.8.0.1024.24'},
    {'osver': '20.10', 'pkgname': 'linux-image-kvm', 'pkgver': '5.8.0.1020.22'},
    {'osver': '20.10', 'pkgname': 'linux-image-lowlatency', 'pkgver': '5.8.0.45.50'},
    {'osver': '20.10', 'pkgname': 'linux-image-lowlatency-hwe-20.04', 'pkgver': '5.8.0.45.50'},
    {'osver': '20.10', 'pkgname': 'linux-image-lowlatency-hwe-20.04-edge', 'pkgver': '5.8.0.45.50'},
    {'osver': '20.10', 'pkgname': 'linux-image-oem-20.04', 'pkgver': '5.8.0.45.50'},
    {'osver': '20.10', 'pkgname': 'linux-image-oracle', 'pkgver': '5.8.0.1022.21'},
    {'osver': '20.10', 'pkgname': 'linux-image-raspi', 'pkgver': '5.8.0.1017.20'},
    {'osver': '20.10', 'pkgname': 'linux-image-raspi-nolpae', 'pkgver': '5.8.0.1017.20'},
    {'osver': '20.10', 'pkgname': 'linux-image-virtual', 'pkgver': '5.8.0.45.50'},
    {'osver': '20.10', 'pkgname': 'linux-image-virtual-hwe-20.04', 'pkgver': '5.8.0.45.50'},
    {'osver': '20.10', 'pkgname': 'linux-image-virtual-hwe-20.04-edge', 'pkgver': '5.8.0.45.50'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-image-5.8.0-1017-raspi / linux-image-5.8.0-1017-raspi-nolpae / etc');
}