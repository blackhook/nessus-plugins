#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5647-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165527);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2021-33655",
    "CVE-2022-1012",
    "CVE-2022-1729",
    "CVE-2022-2503",
    "CVE-2022-32296",
    "CVE-2022-36946"
  );
  script_xref(name:"USN", value:"5647-1");

  script_name(english:"Ubuntu 20.04 LTS : Linux kernel (GCP) vulnerabilities (USN-5647-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-5647-1 advisory.

  - When sending malicous data to kernel by ioctl cmd FBIOPUT_VSCREENINFO,kernel will write memory out of
    bounds. (CVE-2021-33655)

  - A memory leak problem was found in the TCP source port generation algorithm in net/ipv4/tcp.c due to the
    small table perturb size. This flaw may allow an attacker to information leak and may cause a denial of
    service problem. (CVE-2022-1012)

  - A race condition was found the Linux kernel in perf_event_open() which can be exploited by an unprivileged
    user to gain root privileges. The bug allows to build several exploit primitives such as kernel address
    information leak, arbitrary execution, etc. (CVE-2022-1729)

  - Dm-verity is used for extending root-of-trust to root filesystems. LoadPin builds on this property to
    restrict module/firmware loads to just the trusted root filesystem. Device-mapper table reloads currently
    allow users with root privileges to switch out the target with an equivalent dm-linear target and bypass
    verification till reboot. This allows root to bypass LoadPin and can be used to load untrusted and
    unverified kernel modules and firmware, which implies arbitrary kernel execution and persistence for
    peripherals that do not verify firmware updates. We recommend upgrading past commit
    4caae58406f8ceb741603eee460d79bacca9b1b5 (CVE-2022-2503)

  - The Linux kernel before 5.17.9 allows TCP servers to identify clients by observing what source ports are
    used. This occurs because of use of Algorithm 4 (Double-Hash Port Selection Algorithm) of RFC 6056.
    (CVE-2022-32296)

  - nfqnl_mangle in net/netfilter/nfnetlink_queue.c in the Linux kernel through 5.18.14 allows remote
    attackers to cause a denial of service (panic) because, in the case of an nf_queue verdict with a one-byte
    nfta_payload attribute, an skb_pull can encounter a negative skb->len. (CVE-2022-36946)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5647-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32296");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-1012");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1089-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');
include('ksplice.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
var release = chomp(release);
if (! preg(pattern:"^(20\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var machine_kernel_release = get_kb_item_or_exit('Host/uname-r');
if (machine_kernel_release)
{
  if (! preg(pattern:"^(5.4.0-\d{4}-gcp)$", string:machine_kernel_release)) audit(AUDIT_INST_VER_NOT_VULN, 'kernel ' + machine_kernel_release);
  var extra = '';
  var kernel_mappings = {
    "5.4.0-\d{4}-gcp" : "5.4.0-1089"
  };
  var trimmed_kernel_release = ereg_replace(string:machine_kernel_release, pattern:"(-\D+)$", replace:'');
  foreach var kernel_regex (keys(kernel_mappings)) {
    if (preg(pattern:kernel_regex, string:machine_kernel_release)) {
      if (deb_ver_cmp(ver1:trimmed_kernel_release, ver2:kernel_mappings[kernel_regex]) < 0)
      {
        extra = extra + 'Running Kernel level of ' + trimmed_kernel_release + ' does not meet the minimum fixed level of ' + kernel_mappings[kernel_regex] + ' for this advisory.\n\n';
      }
      else
      {
        audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-5647-1');
      }
    }
  }
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2021-33655', 'CVE-2022-1012', 'CVE-2022-1729', 'CVE-2022-2503', 'CVE-2022-32296', 'CVE-2022-36946');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5647-1');
  }
  else
  {
    extra = extra + ksplice_reporting_text();
  }
}
if (extra) {
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : extra
  );
  exit(0);
}
