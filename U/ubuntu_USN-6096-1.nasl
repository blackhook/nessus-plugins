#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6096-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176226);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/23");

  script_cve_id(
    "CVE-2022-3707",
    "CVE-2022-4129",
    "CVE-2022-4842",
    "CVE-2022-27672",
    "CVE-2022-36280",
    "CVE-2022-48423",
    "CVE-2022-48424",
    "CVE-2023-0210",
    "CVE-2023-0394",
    "CVE-2023-0458",
    "CVE-2023-0459",
    "CVE-2023-1073",
    "CVE-2023-1074",
    "CVE-2023-1075",
    "CVE-2023-1078",
    "CVE-2023-1118",
    "CVE-2023-1513",
    "CVE-2023-1652",
    "CVE-2023-2162",
    "CVE-2023-21102",
    "CVE-2023-21106",
    "CVE-2023-23454",
    "CVE-2023-23455",
    "CVE-2023-26544",
    "CVE-2023-32269"
  );
  script_xref(name:"USN", value:"6096-1");

  script_name(english:"Ubuntu 22.04 LTS / 22.10 : Linux kernel vulnerabilities (USN-6096-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS / 22.10 host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-6096-1 advisory.

  - When SMT is enabled, certain AMD processors may speculatively execute instructions using a target from the
    sibling thread after an SMT mode switch potentially resulting in information disclosure. (CVE-2022-27672)

  - An out-of-bounds(OOB) memory access vulnerability was found in vmwgfx driver in
    drivers/gpu/vmxgfx/vmxgfx_kms.c in GPU component in the Linux kernel with device file '/dev/dri/renderD128
    (or Dxxx)'. This flaw allows a local attacker with a user account on the system to gain privilege, causing
    a denial of service(DoS). (CVE-2022-36280)

  - A double-free memory flaw was found in the Linux kernel. The Intel GVT-g graphics driver triggers VGA card
    system resource overload, causing a fail in the intel_gvt_dma_map_guest_page function. This issue could
    allow a local user to crash the system. (CVE-2022-3707)

  - A flaw was found in the Linux kernel's Layer 2 Tunneling Protocol (L2TP). A missing lock when clearing
    sk_user_data can lead to a race condition and NULL pointer dereference. A local user could use this flaw
    to potentially crash the system causing a denial of service. (CVE-2022-4129)

  - A flaw NULL Pointer Dereference in the Linux kernel NTFS3 driver function attr_punch_hole() was found. A
    local user could use this flaw to crash the system. (CVE-2022-4842)

  - In the Linux kernel before 6.1.3, fs/ntfs3/record.c does not validate resident attribute names. An out-of-
    bounds write may occur. (CVE-2022-48423)

  - In the Linux kernel before 6.1.3, fs/ntfs3/inode.c does not validate the attribute name offset. An
    unhandled page fault may occur. (CVE-2022-48424)

  - A bug affects the Linux kernel's ksmbd NTLMv2 authentication and is known to crash the OS immediately in
    Linux-based systems. (CVE-2023-0210)

  - A NULL pointer dereference flaw was found in rawv6_push_pending_frames in net/ipv6/raw.c in the network
    subcomponent in the Linux kernel. This flaw causes the system to crash. (CVE-2023-0394)

  - A speculative pointer dereference problem exists in the Linux Kernel on the do_prlimit() function. The
    resource argument value is controlled and is used in pointer arithmetic for the 'rlim' variable and can be
    used to leak the contents. We recommend upgrading past version 6.1.8 or commit
    739790605705ddcf18f21782b9c99ad7d53a8c11 (CVE-2023-0458)

  - A memory corruption flaw was found in the Linux kernel's human interface device (HID) subsystem in how a
    user inserts a malicious USB device. This flaw allows a local user to crash or potentially escalate their
    privileges on the system. (CVE-2023-1073)

  - A memory leak flaw was found in the Linux kernel's Stream Control Transmission Protocol. This issue may
    occur when a user starts a malicious networking service and someone connects to this service. This could
    allow a local user to starve resources, causing a denial of service. (CVE-2023-1074)

  - A flaw was found in the Linux Kernel. The tls_is_tx_ready() incorrectly checks for list emptiness,
    potentially accessing a type confused entry to the list_head, leaking the last byte of the confused field
    that overlaps with rec->tx_ready. (CVE-2023-1075)

  - A flaw was found in the Linux Kernel in RDS (Reliable Datagram Sockets) protocol. The
    rds_rm_zerocopy_callback() uses list_entry() on the head of a list causing a type confusion. Local user
    can trigger this with rds_message_put(). Type confusion leads to `struct rds_msg_zcopy_info *info`
    actually points to something else that is potentially controlled by local user. It is known how to trigger
    this, which causes an out of bounds access, and a lock corruption. (CVE-2023-1078)

  - A flaw use after free in the Linux kernel integrated infrared receiver/transceiver driver was found in the
    way user detaching rc device. A local user could use this flaw to crash the system or potentially escalate
    their privileges on the system. (CVE-2023-1118)

  - A flaw was found in KVM. When calling the KVM_GET_DEBUGREGS ioctl, on 32-bit systems, there might be some
    uninitialized portions of the kvm_debugregs structure that could be copied to userspace, causing an
    information leak. (CVE-2023-1513)

  - A use-after-free flaw was found in nfsd4_ssc_setup_dul in fs/nfsd/nfs4proc.c in the NFS filesystem in the
    Linux Kernel. This issue could allow a local attacker to crash the system or it may lead to a kernel
    information leak problem. (CVE-2023-1652)

  - In __efi_rt_asm_wrapper of efi-rt-wrapper.S, there is a possible bypass of shadow stack protection due to
    a logic error in the code. This could lead to local escalation of privilege with no additional execution
    privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android
    kernelAndroid ID: A-260821414References: Upstream kernel (CVE-2023-21102)

  - In adreno_set_param of adreno_gpu.c, there is a possible memory corruption due to a double free. This
    could lead to local escalation of privilege with no additional execution privileges needed. User
    interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-265016072References: Upstream kernel (CVE-2023-21106)

  - A use-after-free vulnerability was found in iscsi_sw_tcp_session_create in drivers/scsi/iscsi_tcp.c in
    SCSI sub-component in the Linux Kernel. In this flaw an attacker could leak kernel internal information.
    (CVE-2023-2162)

  - cbq_classify in net/sched/sch_cbq.c in the Linux kernel through 6.1.4 allows attackers to cause a denial
    of service (slab-out-of-bounds read) because of type confusion (non-negative numbers can sometimes
    indicate a TC_ACT_SHOT condition rather than valid classification results). (CVE-2023-23454)

  - atm_tc_enqueue in net/sched/sch_atm.c in the Linux kernel through 6.1.4 allows attackers to cause a denial
    of service because of type confusion (non-negative numbers can sometimes indicate a TC_ACT_SHOT condition
    rather than valid classification results). (CVE-2023-23455)

  - In the Linux kernel 6.0.8, there is a use-after-free in run_unpack in fs/ntfs3/run.c, related to a
    difference between NTFS sector size and media sector size. (CVE-2023-26544)

  - An issue was discovered in the Linux kernel before 6.1.11. In net/netrom/af_netrom.c, there is a use-
    after-free because accept is also allowed for a successfully connected AF_NETROM socket. However, in order
    for an attacker to exploit this, the system must have netrom routing configured or the attacker must have
    the CAP_NET_ADMIN capability. (CVE-2023-32269)

  - In the Linux kernel before 6.1.6, a NULL pointer dereference bug in the traffic control subsystem allows
    an unprivileged user to trigger a denial of service (system crash) via a crafted traffic control
    configuration that is set up with tc qdisc and tc class commands. This affects qdisc_graft in
    net/sched/sch_api.c. (CVE-2022-47929) (CVE-2023-0459)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6096-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-26544");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image--generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image--generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image--generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.19.0-1024-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.19.0-42--generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.19.0-42--generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.19.0-42--generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
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
if (! preg(pattern:"^(22\.04|22\.10)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var machine_kernel_release = get_kb_item_or_exit('Host/uname-r');
if (machine_kernel_release)
{
  var kernel_pattern;
  var kernel_mappings;
  var extra = '';
  if (preg(pattern:"^22.04$", string:os_release)) {
    kernel_pattern = "^5.19.0-\d+-(generic|generic-64k|generic-lpae)$";
    kernel_mappings = {
            "5.19.0-\d+(-generic|-generic-64k|-generic-lpae)" : "5.19.0-42"
    };
  };
  if (preg(pattern:"^22.10$", string:os_release)) {
    kernel_pattern = "^(5.19.0-\d+-gcp)$";
    kernel_mappings = {
            "5.19.0-\d+-gcp" : "5.19.0-1024"
    };
  };
  if (! preg(pattern:kernel_pattern, string:machine_kernel_release)) audit(AUDIT_INST_VER_NOT_VULN, 'kernel ' + machine_kernel_release);

  var trimmed_kernel_release = ereg_replace(string:machine_kernel_release, pattern:"(-\D.*?)$", replace:'');
  foreach var kernel_regex (keys(kernel_mappings)) {
    if (preg(pattern:kernel_regex, string:machine_kernel_release)) {
      if (deb_ver_cmp(ver1:trimmed_kernel_release, ver2:kernel_mappings[kernel_regex]) < 0)
      {
        extra = extra + 'Running Kernel level of ' + trimmed_kernel_release + ' does not meet the minimum fixed level of ' + kernel_mappings[kernel_regex] + ' for this advisory.\n\n';
      }
      else
      {
        audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-6096-1');
      }
    }
  }
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2022-3707', 'CVE-2022-4129', 'CVE-2022-4842', 'CVE-2022-27672', 'CVE-2022-36280', 'CVE-2022-48423', 'CVE-2022-48424', 'CVE-2023-0210', 'CVE-2023-0394', 'CVE-2023-0458', 'CVE-2023-0459', 'CVE-2023-1073', 'CVE-2023-1074', 'CVE-2023-1075', 'CVE-2023-1078', 'CVE-2023-1118', 'CVE-2023-1513', 'CVE-2023-1652', 'CVE-2023-2162', 'CVE-2023-21102', 'CVE-2023-21106', 'CVE-2023-23454', 'CVE-2023-23455', 'CVE-2023-26544', 'CVE-2023-32269');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-6096-1');
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
