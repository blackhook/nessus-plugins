##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5505-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162822);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2021-3609",
    "CVE-2021-3752",
    "CVE-2021-3760",
    "CVE-2021-4197",
    "CVE-2021-4202",
    "CVE-2021-39685",
    "CVE-2021-39714",
    "CVE-2022-0330",
    "CVE-2022-1353",
    "CVE-2022-1419",
    "CVE-2022-1652",
    "CVE-2022-1679",
    "CVE-2022-1734",
    "CVE-2022-21123",
    "CVE-2022-21125",
    "CVE-2022-21166",
    "CVE-2022-24958",
    "CVE-2022-28356",
    "CVE-2022-28388"
  );
  script_xref(name:"USN", value:"5505-1");

  script_name(english:"Ubuntu 16.04 ESM : Linux kernel vulnerabilities (USN-5505-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-5505-1 advisory.

  - .A flaw was found in the CAN BCM networking protocol in the Linux kernel, where a local attacker can abuse
    a flaw in the CAN subsystem to corrupt memory, crash the system or escalate privileges. This race
    condition in net/can/bcm.c in the Linux kernel allows for local privilege escalation to root.
    (CVE-2021-3609)

  - A use-after-free flaw was found in the Linux kernel's Bluetooth subsystem in the way user calls connect to
    the socket and disconnect simultaneously due to a race condition. This flaw allows a user to crash the
    system or escalate their privileges. The highest threat from this vulnerability is to confidentiality,
    integrity, as well as system availability. (CVE-2021-3752)

  - A flaw was found in the Linux kernel. A use-after-free vulnerability in the NFC stack can lead to a threat
    to confidentiality, integrity, and system availability. (CVE-2021-3760)

  - An unprivileged write to the file handler flaw in the Linux kernel's control groups and namespaces
    subsystem was found in the way users have access to some less privileged process that are controlled by
    cgroups and have higher privileged parent process. It is actually both for cgroup2 and cgroup1 versions of
    control groups. A local user could use this flaw to crash the system or escalate their privileges on the
    system. (CVE-2021-4197)

  - A use-after-free flaw was found in nci_request in net/nfc/nci/core.c in NFC Controller Interface (NCI) in
    the Linux kernel. This flaw could allow a local attacker with user privileges to cause a data race problem
    while the device is getting removed, leading to a privilege escalation problem. (CVE-2021-4202)

  - In various setup methods of the USB gadget subsystem, there is a possible out of bounds write due to an
    incorrect flag check. This could lead to local escalation of privilege with no additional execution
    privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android
    kernelAndroid ID: A-210292376References: Upstream kernel (CVE-2021-39685)

  - In ion_buffer_kmap_get of ion.c, there is a possible use-after-free due to an integer overflow. This could
    lead to local escalation of privilege with no additional execution privileges needed. User interaction is
    not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-205573273References:
    Upstream kernel (CVE-2021-39714)

  - A random memory access flaw was found in the Linux kernel's GPU i915 kernel driver functionality in the
    way a user may run malicious code on the GPU. This flaw allows a local user to crash the system or
    escalate their privileges on the system. (CVE-2022-0330)

  - A vulnerability was found in the pfkey_register function in net/key/af_key.c in the Linux kernel. This
    flaw allows a local, unprivileged user to gain access to kernel memory, leading to a system crash or a
    leak of internal kernel information. (CVE-2022-1353)

  - The root cause of this vulnerability is that the ioctl$DRM_IOCTL_MODE_DESTROY_DUMB can decrease refcount
    of *drm_vgem_gem_object *(created in *vgem_gem_dumb_create*) concurrently, and *vgem_gem_dumb_create *will
    access the freed drm_vgem_gem_object. (CVE-2022-1419)

  - Linux Kernel could allow a local attacker to execute arbitrary code on the system, caused by a concurrency
    use-after-free flaw in the bad_flp_intr function. By executing a specially-crafted program, an attacker
    could exploit this vulnerability to execute arbitrary code or cause a denial of service condition on the
    system. (CVE-2022-1652)

  - A use-after-free flaw was found in the Linux kernel's Atheros wireless adapter driver in the way a user
    forces the ath9k_htc_wait_for_target function to fail with some input messages. This flaw allows a local
    user to crash or potentially escalate their privileges on the system. (CVE-2022-1679)

  - A flaw in Linux Kernel found in nfcmrvl_nci_unregister_dev() in drivers/nfc/nfcmrvl/main.c can lead to use
    after free both read or write when non synchronized between cleanup routine and firmware download routine.
    (CVE-2022-1734)

  - Incomplete cleanup of multi-core shared buffers for some Intel(R) Processors may allow an authenticated
    user to potentially enable information disclosure via local access. (CVE-2022-21123)

  - Incomplete cleanup of microarchitectural fill buffers on some Intel(R) Processors may allow an
    authenticated user to potentially enable information disclosure via local access. (CVE-2022-21125)

  - Incomplete cleanup in specific special register write operations for some Intel(R) Processors may allow an
    authenticated user to potentially enable information disclosure via local access. (CVE-2022-21166)

  - drivers/usb/gadget/legacy/inode.c in the Linux kernel through 5.16.8 mishandles dev->buf release.
    (CVE-2022-24958)

  - In the Linux kernel before 5.17.1, a refcount leak bug was found in net/llc/af_llc.c. (CVE-2022-28356)

  - usb_8dev_start_xmit in drivers/net/can/usb/usb_8dev.c in the Linux kernel through 5.17.1 has a double
    free. (CVE-2022-28388)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5505-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3752");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-28388");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1110-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
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
if (! preg(pattern:"^(16\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var machine_kernel_release = get_kb_item_or_exit('Host/uname-r');
if (machine_kernel_release)
{
  if (! preg(pattern:"^(4.4.0-\d{4}-kvm)$", string:machine_kernel_release)) audit(AUDIT_INST_VER_NOT_VULN, 'kernel ' + machine_kernel_release);
  var extra = '';
  var kernel_mappings = {
    "4.4.0-\d{4}-kvm" : "4.4.0-1110"
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
        audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-5505-1');
      }
    }
  }
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2021-3609', 'CVE-2021-3752', 'CVE-2021-3760', 'CVE-2021-4197', 'CVE-2021-4202', 'CVE-2021-39685', 'CVE-2021-39714', 'CVE-2022-0330', 'CVE-2022-1353', 'CVE-2022-1419', 'CVE-2022-1652', 'CVE-2022-1679', 'CVE-2022-1734', 'CVE-2022-21123', 'CVE-2022-21125', 'CVE-2022-21166', 'CVE-2022-24958', 'CVE-2022-28356', 'CVE-2022-28388');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5505-1');
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
