##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5467-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161950);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2021-3772",
    "CVE-2021-4197",
    "CVE-2022-1011",
    "CVE-2022-1158",
    "CVE-2022-1198",
    "CVE-2022-1353",
    "CVE-2022-1516",
    "CVE-2022-1966",
    "CVE-2022-21499",
    "CVE-2022-23036",
    "CVE-2022-23037",
    "CVE-2022-23038",
    "CVE-2022-23039",
    "CVE-2022-23040",
    "CVE-2022-23041",
    "CVE-2022-23042",
    "CVE-2022-24958",
    "CVE-2022-26966",
    "CVE-2022-28356",
    "CVE-2022-28389",
    "CVE-2022-28390"
  );
  script_xref(name:"USN", value:"5467-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : Linux kernel vulnerabilities (USN-5467-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-5467-1 advisory.

  - A flaw was found in the Linux SCTP stack. A blind attacker may be able to kill an existing SCTP
    association through invalid chunks if the attacker knows the IP-addresses and port numbers being used and
    the attacker can send packets with spoofed IP addresses. (CVE-2021-3772)

  - An unprivileged write to the file handler flaw in the Linux kernel's control groups and namespaces
    subsystem was found in the way users have access to some less privileged process that are controlled by
    cgroups and have higher privileged parent process. It is actually both for cgroup2 and cgroup1 versions of
    control groups. A local user could use this flaw to crash the system or escalate their privileges on the
    system. (CVE-2021-4197)

  - A use-after-free flaw was found in the Linux kernel's FUSE filesystem in the way a user triggers write().
    This flaw allows a local user to gain unauthorized access to data from the FUSE filesystem, resulting in
    privilege escalation. (CVE-2022-1011)

  - A vulnerability was found in the pfkey_register function in net/key/af_key.c in the Linux kernel. This
    flaw allows a local, unprivileged user to gain access to kernel memory, leading to a system crash or a
    leak of internal kernel information. (CVE-2022-1353)

  - A NULL pointer dereference flaw was found in the Linux kernel's X.25 set of standardized network protocols
    functionality in the way a user terminates their session using a simulated Ethernet card and continued
    usage of this connection. This flaw allows a local user to crash the system. (CVE-2022-1516)

  - A use-after-free vulnerability was found in the Linux kernel's Netfilter subsystem in
    net/netfilter/nf_tables_api.c. This flaw allows a local attacker with user access to cause a privilege
    escalation issue. (CVE-2022-1966)

  - Linux PV device frontends vulnerable to attacks by backends T[his CNA information record relates to
    multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Several Linux PV
    device frontends are using the grant table interfaces for removing access rights of the backends in ways
    being subject to race conditions, resulting in potential data leaks, data corruption by malicious
    backends, and denial of service triggered by malicious backends: blkfront, netfront, scsifront and the
    gntalloc driver are testing whether a grant reference is still in use. If this is not the case, they
    assume that a following removal of the granted access will always succeed, which is not true in case the
    backend has mapped the granted page between those two operations. As a result the backend can keep access
    to the memory page of the guest no matter how the page will be used after the frontend I/O has finished.
    The xenbus driver has a similar problem, as it doesn't check the success of removing the granted access of
    a shared ring buffer. blkfront: CVE-2022-23036 netfront: CVE-2022-23037 scsifront: CVE-2022-23038
    gntalloc: CVE-2022-23039 xenbus: CVE-2022-23040 blkfront, netfront, scsifront, usbfront, dmabuf, xenbus,
    9p, kbdfront, and pvcalls are using a functionality to delay freeing a grant reference until it is no
    longer in use, but the freeing of the related data page is not synchronized with dropping the granted
    access. As a result the backend can keep access to the memory page even after it has been freed and then
    re-used for a different purpose. CVE-2022-23041 netfront will fail a BUG_ON() assertion if it fails to
    revoke access in the rx path. This will result in a Denial of Service (DoS) situation of the guest which
    can be triggered by the backend. CVE-2022-23042 (CVE-2022-23036, CVE-2022-23037, CVE-2022-23038,
    CVE-2022-23039, CVE-2022-23040, CVE-2022-23041, CVE-2022-23042)

  - drivers/usb/gadget/legacy/inode.c in the Linux kernel through 5.16.8 mishandles dev->buf release.
    (CVE-2022-24958)

  - An issue was discovered in the Linux kernel before 5.16.12. drivers/net/usb/sr9700.c allows attackers to
    obtain sensitive information from heap memory via crafted frame lengths from a device. (CVE-2022-26966)

  - In the Linux kernel before 5.17.1, a refcount leak bug was found in net/llc/af_llc.c. (CVE-2022-28356)

  - mcba_usb_start_xmit in drivers/net/can/usb/mcba_usb.c in the Linux kernel through 5.17.1 has a double
    free. (CVE-2022-28389)

  - ems_usb_start_xmit in drivers/net/can/usb/ems_usb.c in the Linux kernel through 5.17.1 has a double free.
    (CVE-2022-28390)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5467-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4197");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-28390");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1026-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1046-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1065-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1068-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1074-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1076-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1078-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1078-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1083-azurefde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-117-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-117-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-117-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azurefde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi");
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
if (! preg(pattern:"^(18\.04|20\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var machine_kernel_release = get_kb_item_or_exit('Host/uname-r');
if (machine_kernel_release)
{
  if (! preg(pattern:"^(5.4.0-\d{3}-(generic|generic-lpae|lowlatency)|5.4.0-\d{4}-(aws|azure-fde|gcp|gke|gkeop|ibm|kvm|oracle|raspi))$", string:machine_kernel_release)) audit(AUDIT_INST_VER_NOT_VULN, 'kernel ' + machine_kernel_release);
  var extra = '';
  var kernel_mappings = {
    "5.4.0-\d{3}-(generic|generic-lpae|lowlatency)" : "5.4.0-117",
    "5.4.0-\d{4}-(aws|gcp)" : "5.4.0-1078",
    "5.4.0-\d{4}-azure-fde" : "5.4.0-1083",
    "5.4.0-\d{4}-gke" : "5.4.0-1074",
    "5.4.0-\d{4}-gkeop" : "5.4.0-1046",
    "5.4.0-\d{4}-ibm" : "5.4.0-1026",
    "5.4.0-\d{4}-kvm" : "5.4.0-1068",
    "5.4.0-\d{4}-oracle" : "5.4.0-1076",
    "5.4.0-\d{4}-raspi" : "5.4.0-1065"
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
        audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-5467-1');
      }
    }
  }
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2021-3772', 'CVE-2021-4197', 'CVE-2022-1011', 'CVE-2022-1158', 'CVE-2022-1198', 'CVE-2022-1353', 'CVE-2022-1516', 'CVE-2022-1966', 'CVE-2022-21499', 'CVE-2022-23036', 'CVE-2022-23037', 'CVE-2022-23038', 'CVE-2022-23039', 'CVE-2022-23040', 'CVE-2022-23041', 'CVE-2022-23042', 'CVE-2022-24958', 'CVE-2022-26966', 'CVE-2022-28356', 'CVE-2022-28389', 'CVE-2022-28390');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5467-1');
  }
  else
  {
    extra = extra + ksplice_reporting_text();
  }
}
if (extra) {
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : extra
  );
  exit(0);
}
