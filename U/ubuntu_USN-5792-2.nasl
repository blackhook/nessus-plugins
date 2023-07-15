#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5792-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169726);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/22");

  script_cve_id(
    "CVE-2022-0171",
    "CVE-2022-2663",
    "CVE-2022-3061",
    "CVE-2022-3303",
    "CVE-2022-3586",
    "CVE-2022-3646",
    "CVE-2022-3649",
    "CVE-2022-4095",
    "CVE-2022-20421",
    "CVE-2022-39188",
    "CVE-2022-39842",
    "CVE-2022-40307",
    "CVE-2022-43750"
  );
  script_xref(name:"USN", value:"5792-2");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS : Linux kernel vulnerabilities (USN-5792-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-5792-2 advisory.

  - A flaw was found in the Linux kernel. The existing KVM SEV API has a vulnerability that allows a non-root
    (host) user-level application to crash the host kernel by creating a confidential guest VM instance in AMD
    CPU that supports Secure Encrypted Virtualization (SEV). (CVE-2022-0171)

  - An issue was found in the Linux kernel in nf_conntrack_irc where the message handling can be confused and
    incorrectly matches the message. A firewall may be able to be bypassed when users are using unencrypted
    IRC with nf_conntrack_irc configured. (CVE-2022-2663)

  - Found Linux Kernel flaw in the i740 driver. The Userspace program could pass any values to the driver
    through ioctl() interface. The driver doesn't check the value of 'pixclock', so it may cause a divide by
    zero error. (CVE-2022-3061)

  - A race condition flaw was found in the Linux kernel sound subsystem due to improper locking. It could lead
    to a NULL pointer dereference while handling the SNDCTL_DSP_SYNC ioctl. A privileged local user (root or
    member of the audio group) could use this flaw to crash the system, resulting in a denial of service
    condition (CVE-2022-3303)

  - A flaw was found in the Linux kernel's networking code. A use-after-free was found in the way the sch_sfb
    enqueue function used the socket buffer (SKB) cb field after the same SKB had been enqueued (and freed)
    into a child qdisc. This flaw allows a local, unprivileged user to crash the system, causing a denial of
    service. (CVE-2022-3586)

  - A vulnerability, which was classified as problematic, has been found in Linux Kernel. This issue affects
    the function nilfs_attach_log_writer of the file fs/nilfs2/segment.c of the component BPF. The
    manipulation leads to memory leak. The attack may be initiated remotely. It is recommended to apply a
    patch to fix this issue. The identifier VDB-211961 was assigned to this vulnerability. (CVE-2022-3646)

  - A vulnerability was found in Linux Kernel. It has been classified as problematic. Affected is the function
    nilfs_new_inode of the file fs/nilfs2/inode.c of the component BPF. The manipulation leads to use after
    free. It is possible to launch the attack remotely. It is recommended to apply a patch to fix this issue.
    The identifier of this vulnerability is VDB-211992. (CVE-2022-3649)

  - In binder_inc_ref_for_node of binder.c, there is a possible way to corrupt memory due to a use after free.
    This could lead to local escalation of privilege with no additional execution privileges needed. User
    interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-239630375References: Upstream kernel (CVE-2022-20421)

  - An issue was discovered in include/asm-generic/tlb.h in the Linux kernel before 5.19. Because of a race
    condition (unmap_mapping_range versus munmap), a device driver can free a page while it still has stale
    TLB entries. This only occurs in situations with VM_PFNMAP VMAs. (CVE-2022-39188)

  - ** DISPUTED ** An issue was discovered in the Linux kernel before 5.19. In pxa3xx_gcu_write in
    drivers/video/fbdev/pxa3xx-gcu.c, the count parameter has a type conflict of size_t versus int, causing an
    integer overflow and bypassing the size check. After that, because it is used as the third argument to
    copy_from_user(), a heap overflow may occur. NOTE: the original discoverer disputes that the overflow can
    actually happen. (CVE-2022-39842)

  - An issue was discovered in the Linux kernel through 5.19.8. drivers/firmware/efi/capsule-loader.c has a
    race condition with a resultant use-after-free. (CVE-2022-40307)

  - drivers/usb/mon/mon_bin.c in usbmon in the Linux kernel before 5.19.15 and 6.x before 6.0.1 allows a user-
    space client to corrupt the monitor's internal memory. (CVE-2022-43750)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5792-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20421");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1027-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1030-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1030-azurefde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azurefde");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023 Canonical, Inc. / NASL script (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(20\.04|22\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var machine_kernel_release = get_kb_item_or_exit('Host/uname-r');
if (machine_kernel_release)
{
  if (! preg(pattern:"^(5.15.0-\d{4}-(aws|azure|azure-fde))$", string:machine_kernel_release)) audit(AUDIT_INST_VER_NOT_VULN, 'kernel ' + machine_kernel_release);
  var extra = '';
  var kernel_mappings = {
    "5.15.0-\d{4}-aws" : "5.15.0-1027",
    "5.15.0-\d{4}-azure" : "5.15.0-1030",
    "5.15.0-\d{4}-azure-fde" : "5.15.0-1030"
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
        audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-5792-2');
      }
    }
  }
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2022-0171', 'CVE-2022-2663', 'CVE-2022-3061', 'CVE-2022-3303', 'CVE-2022-3586', 'CVE-2022-3646', 'CVE-2022-3649', 'CVE-2022-4095', 'CVE-2022-20421', 'CVE-2022-39188', 'CVE-2022-39842', 'CVE-2022-40307', 'CVE-2022-43750');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5792-2');
  }
  else
  {
    extra = extra + ksplice_reporting_text();
  }
}
if (extra) {
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : extra
  );
  exit(0);
}
