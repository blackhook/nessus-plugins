#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5695-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166414);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2022-0812",
    "CVE-2022-1012",
    "CVE-2022-2318",
    "CVE-2022-26365",
    "CVE-2022-32296",
    "CVE-2022-33740",
    "CVE-2022-33741",
    "CVE-2022-33742",
    "CVE-2022-33744"
  );
  script_xref(name:"USN", value:"5695-1");

  script_name(english:"Ubuntu 16.04 ESM : Linux kernel (GCP) vulnerabilities (USN-5695-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-5695-1 advisory.

  - An information leak flaw was found in NFS over RDMA in the net/sunrpc/xprtrdma/rpc_rdma.c in the Linux
    Kernel. This flaw allows an attacker with normal user privileges to leak kernel information.
    (CVE-2022-0812)

  - A memory leak problem was found in the TCP source port generation algorithm in net/ipv4/tcp.c due to the
    small table perturb size. This flaw may allow an attacker to information leak and may cause a denial of
    service problem. (CVE-2022-1012)

  - There are use-after-free vulnerabilities caused by timer handler in net/rose/rose_timer.c of linux that
    allow attackers to crash linux kernel without any privileges. (CVE-2022-2318)

  - Linux disk/nic frontends data leaks T[his CNA information record relates to multiple CVEs; the text
    explains which aspects/vulnerabilities correspond to which CVE.] Linux Block and Network PV device
    frontends don't zero memory regions before sharing them with the backend (CVE-2022-26365, CVE-2022-33740).
    Additionally the granularity of the grant table doesn't allow sharing less than a 4K page, leading to
    unrelated data residing in the same 4K page as data shared with a backend being accessible by such backend
    (CVE-2022-33741, CVE-2022-33742). (CVE-2022-26365, CVE-2022-33740, CVE-2022-33741, CVE-2022-33742)

  - The Linux kernel before 5.17.9 allows TCP servers to identify clients by observing what source ports are
    used. This occurs because of use of Algorithm 4 (Double-Hash Port Selection Algorithm) of RFC 6056.
    (CVE-2022-32296)

  - Arm guests can cause Dom0 DoS via PV devices When mapping pages of guests on Arm, dom0 is using an rbtree
    to keep track of the foreign mappings. Updating of that rbtree is not always done completely with the
    related lock held, resulting in a small race window, which can be used by unprivileged guests via PV
    devices to cause inconsistencies of the rbtree. These inconsistencies can lead to Denial of Service (DoS)
    of dom0, e.g. by causing crashes or the inability to perform further mappings of other guests' memory
    pages. (CVE-2022-33744)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5695-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-33742");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-1012");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1137-gcp");
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
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! preg(pattern:"^(16\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var machine_kernel_release = get_kb_item_or_exit('Host/uname-r');
if (machine_kernel_release)
{
  if (! preg(pattern:"^(4.15.0-\d{4}-gcp)$", string:machine_kernel_release)) audit(AUDIT_INST_VER_NOT_VULN, 'kernel ' + machine_kernel_release);
  var extra = '';
  var kernel_mappings = {
    "4.15.0-\d{4}-gcp" : "4.15.0-1137"
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
        audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-5695-1');
      }
    }
  }
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2022-0812', 'CVE-2022-1012', 'CVE-2022-2318', 'CVE-2022-26365', 'CVE-2022-32296', 'CVE-2022-33740', 'CVE-2022-33741', 'CVE-2022-33742', 'CVE-2022-33744');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5695-1');
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
