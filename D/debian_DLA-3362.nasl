#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3362. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(172554);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/15");

  script_cve_id(
    "CVE-2020-14394",
    "CVE-2020-17380",
    "CVE-2020-29130",
    "CVE-2021-3409",
    "CVE-2021-3592",
    "CVE-2021-3593",
    "CVE-2021-3594",
    "CVE-2021-3595",
    "CVE-2022-0216",
    "CVE-2022-1050"
  );
  script_xref(name:"IAVB", value:"2020-B-0075-S");

  script_name(english:"Debian DLA-3362-1 : qemu - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3362 advisory.

  - An infinite loop flaw was found in the USB xHCI controller emulation of QEMU while computing the length of
    the Transfer Request Block (TRB) Ring. This flaw allows a privileged guest user to hang the QEMU process
    on the host, resulting in a denial of service. (CVE-2020-14394)

  - A heap-based buffer overflow was found in QEMU through 5.0.0 in the SDHCI device emulation support. It
    could occur while doing a multi block SDMA transfer via the sdhci_sdma_transfer_multi_blocks() routine in
    hw/sd/sdhci.c. A guest user or process could use this flaw to crash the QEMU process on the host,
    resulting in a denial of service condition, or potentially execute arbitrary code with privileges of the
    QEMU process on the host. (CVE-2020-17380)

  - slirp.c in libslirp through 4.3.1 has a buffer over-read because it tries to read a certain amount of
    header data even if that exceeds the total packet length. (CVE-2020-29130)

  - The patch for CVE-2020-17380/CVE-2020-25085 was found to be ineffective, thus making QEMU vulnerable to
    the out-of-bounds read/write access issues previously found in the SDHCI controller emulation code. This
    flaw allows a malicious privileged guest to crash the QEMU process on the host, resulting in a denial of
    service or potential code execution. QEMU up to (including) 5.2.0 is affected by this. (CVE-2021-3409)

  - An invalid pointer initialization issue was found in the SLiRP networking implementation of QEMU. The flaw
    exists in the bootp_input() function and could occur while processing a udp packet that is smaller than
    the size of the 'bootp_t' structure. A malicious guest could use this flaw to leak 10 bytes of
    uninitialized heap memory from the host. The highest threat from this vulnerability is to data
    confidentiality. This flaw affects libslirp versions prior to 4.6.0. (CVE-2021-3592)

  - An invalid pointer initialization issue was found in the SLiRP networking implementation of QEMU. The flaw
    exists in the udp6_input() function and could occur while processing a udp packet that is smaller than the
    size of the 'udphdr' structure. This issue may lead to out-of-bounds read access or indirect host memory
    disclosure to the guest. The highest threat from this vulnerability is to data confidentiality. This flaw
    affects libslirp versions prior to 4.6.0. (CVE-2021-3593)

  - An invalid pointer initialization issue was found in the SLiRP networking implementation of QEMU. The flaw
    exists in the udp_input() function and could occur while processing a udp packet that is smaller than the
    size of the 'udphdr' structure. This issue may lead to out-of-bounds read access or indirect host memory
    disclosure to the guest. The highest threat from this vulnerability is to data confidentiality. This flaw
    affects libslirp versions prior to 4.6.0. (CVE-2021-3594)

  - An invalid pointer initialization issue was found in the SLiRP networking implementation of QEMU. The flaw
    exists in the tftp_input() function and could occur while processing a udp packet that is smaller than the
    size of the 'tftp_t' structure. This issue may lead to out-of-bounds read access or indirect host memory
    disclosure to the guest. The highest threat from this vulnerability is to data confidentiality. This flaw
    affects libslirp versions prior to 4.6.0. (CVE-2021-3595)

  - A use-after-free vulnerability was found in the LSI53C895A SCSI Host Bus Adapter emulation of QEMU. The
    flaw occurs while processing repeated messages to cancel the current SCSI request via the lsi_do_msgout
    function. This flaw allows a malicious privileged user within the guest to crash the QEMU process on the
    host, resulting in a denial of service. (CVE-2022-0216)

  - A flaw was found in the QEMU implementation of VMWare's paravirtual RDMA device. This flaw allows a
    crafted guest driver to execute HW commands when shared buffers are not yet allocated, potentially leading
    to a use-after-free condition. (CVE-2022-1050)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=970937");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/qemu");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3362");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-14394");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-17380");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-29130");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3409");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3592");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3593");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3594");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3595");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0216");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1050");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/qemu");
  script_set_attribute(attribute:"solution", value:
"Upgrade the qemu packages.

For Debian 10 buster, these problems have been fixed in version 1");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1050");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-block-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-mips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-ppc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-sparc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-user-binfmt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-user-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'qemu', 'reference': '1:3.1+dfsg-8+deb10u10'},
    {'release': '10.0', 'prefix': 'qemu-block-extra', 'reference': '1:3.1+dfsg-8+deb10u10'},
    {'release': '10.0', 'prefix': 'qemu-guest-agent', 'reference': '1:3.1+dfsg-8+deb10u10'},
    {'release': '10.0', 'prefix': 'qemu-kvm', 'reference': '1:3.1+dfsg-8+deb10u10'},
    {'release': '10.0', 'prefix': 'qemu-system', 'reference': '1:3.1+dfsg-8+deb10u10'},
    {'release': '10.0', 'prefix': 'qemu-system-arm', 'reference': '1:3.1+dfsg-8+deb10u10'},
    {'release': '10.0', 'prefix': 'qemu-system-common', 'reference': '1:3.1+dfsg-8+deb10u10'},
    {'release': '10.0', 'prefix': 'qemu-system-data', 'reference': '1:3.1+dfsg-8+deb10u10'},
    {'release': '10.0', 'prefix': 'qemu-system-gui', 'reference': '1:3.1+dfsg-8+deb10u10'},
    {'release': '10.0', 'prefix': 'qemu-system-mips', 'reference': '1:3.1+dfsg-8+deb10u10'},
    {'release': '10.0', 'prefix': 'qemu-system-misc', 'reference': '1:3.1+dfsg-8+deb10u10'},
    {'release': '10.0', 'prefix': 'qemu-system-ppc', 'reference': '1:3.1+dfsg-8+deb10u10'},
    {'release': '10.0', 'prefix': 'qemu-system-sparc', 'reference': '1:3.1+dfsg-8+deb10u10'},
    {'release': '10.0', 'prefix': 'qemu-system-x86', 'reference': '1:3.1+dfsg-8+deb10u10'},
    {'release': '10.0', 'prefix': 'qemu-user', 'reference': '1:3.1+dfsg-8+deb10u10'},
    {'release': '10.0', 'prefix': 'qemu-user-binfmt', 'reference': '1:3.1+dfsg-8+deb10u10'},
    {'release': '10.0', 'prefix': 'qemu-user-static', 'reference': '1:3.1+dfsg-8+deb10u10'},
    {'release': '10.0', 'prefix': 'qemu-utils', 'reference': '1:3.1+dfsg-8+deb10u10'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qemu / qemu-block-extra / qemu-guest-agent / qemu-kvm / qemu-system / etc');
}
