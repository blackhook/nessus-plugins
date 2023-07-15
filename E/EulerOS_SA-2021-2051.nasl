#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151238);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2020-27171",
    "CVE-2020-35519",
    "CVE-2020-36310",
    "CVE-2020-36311",
    "CVE-2020-36312",
    "CVE-2020-36313",
    "CVE-2020-36322",
    "CVE-2021-3483",
    "CVE-2021-20292",
    "CVE-2021-23133",
    "CVE-2021-28660",
    "CVE-2021-28964",
    "CVE-2021-28971",
    "CVE-2021-29154",
    "CVE-2021-29264",
    "CVE-2021-29647",
    "CVE-2021-29650",
    "CVE-2021-30002"
  );

  script_name(english:"EulerOS 2.0 SP9 : kernel (EulerOS-SA-2021-2051)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A flaw was found in the Nosy driver in the Linux
    kernel. This issue allows a device to be inserted twice
    into a doubly-linked list, leading to a use-after-free
    when one of these devices is removed. The highest
    threat from this vulnerability is to confidentiality,
    integrity, as well as system
    availability.(CVE-2021-3483)

  - An issue was discovered in the Linux kernel before
    5.11.3 when a webcam device exists. video_usercopy in
    drivers/media/v4l2-core/v4l2-ioctl.c has a memory leak
    for large arguments, aka
    CID-fb18802a338b.(CVE-2021-30002)

  - An issue was discovered in the FUSE filesystem
    implementation in the Linux kernel before 5.10.6, aka
    CID-5d069dbe8aaf. fuse_do_getattr() calls
    make_bad_inode() in inappropriate situations, causing a
    system crash. NOTE: the original fix for this
    vulnerability was incomplete, and its incompleteness is
    tracked as CVE-2021-28950.(CVE-2020-36322)

  - There is a flaw reported in
    drivers/gpu/drm/nouveau/nouveau_sgdma.c in
    nouveau_sgdma_create_ttm in Nouveau DRM subsystem. The
    issue results from the lack of validating the existence
    of an object prior to performing operations on the
    object. An attacker with a local account with a root
    privilege, can leverage this vulnerability to escalate
    privileges and execute code in the context of the
    kernel.(CVE-2021-20292)

  - An issue was discovered in the Linux kernel before 5.8.
    arch/x86/kvm/svm/svm.c allows a set_memory_region_test
    infinite loop for certain nested page faults, aka
    CID-e72436bc3a52.(CVE-2020-36310)

  - A race condition was found in the Linux kernel in
    sctp_destroy_sock. If sctp_destroy_sock is called
    without sock_net(sk)->sctp.addr_wq_lock held and
    sp->do_auto_asconf is true, then an element is removed
    from the auto_asconf_splist without any proper locking.
    This can lead to kernel privilege escalation from the
    context of a network service or from an unprivileged
    process if certain conditions are met.(CVE-2021-23133)

  - In intel_pmu_drain_pebs_nhm in
    arch/x86/events/intel/ds.c in the Linux kernel through
    5.11.8 on some Haswell CPUs, userspace applications
    (such as perf-fuzzer) can cause a system crash because
    the PEBS status in a PEBS record is mishandled, aka
    CID-d88d05a9e0b6.(CVE-2021-28971)

  - BPF JIT compilers in the Linux kernel through 5.11.12
    have incorrect computation of branch displacements,
    allowing them to execute arbitrary code within the
    kernel context. This affects
    arch/x86/net/bpf_jit_comp.c and
    arch/x86/net/bpf_jit_comp32.c.(CVE-2021-29154)

  - An issue was discovered in the Linux kernel before
    5.11.11. qrtr_recvmsg in net/qrtr/qrtr.c allows
    attackers to obtain sensitive information from kernel
    memory because of a partially uninitialized data
    structure, aka CID-50535249f624.(CVE-2021-29647)

  - An issue was discovered in the Linux kernel before 5.7.
    The KVM subsystem allows out-of-range access to
    memslots after a deletion, aka CID-0774a964ef56. This
    affects arch/s390/kvm/kvm-s390.c,
    include/linux/kvm_host.h, and
    virt/kvm/kvm_main.c.(CVE-2020-36313)

  - A race condition was discovered in get_old_root in
    fs/btrfs/ctree.c in the Linux kernel through 5.11.8. It
    allows attackers to cause a denial of service (BUG)
    because of a lack of locking on an extent buffer before
    a cloning operation, aka
    CID-dbcc7d57bffc.(CVE-2021-28964)

  - An issue was discovered in the Linux kernel through
    5.11.10. drivers/net/ethernet/freescale/gianfar.c in
    the Freescale Gianfar Ethernet driver allows attackers
    to cause a system crash because a negative fragment
    size is calculated in situations involving an rx queue
    overrun when jumbo packets are used and NAPI is
    enabled, aka CID-d8861bab48b6.(CVE-2021-29264)

  - An issue was discovered in the Linux kernel before
    5.11.8. kernel/bpf/verifier.c has an off-by-one error
    (with a resultant integer underflow) affecting
    out-of-bounds speculation on pointer arithmetic,
    leading to side-channel attacks that defeat Spectre
    mitigations and obtain sensitive information from
    kernel memory, aka CID-10d2bb2e6b1d.(CVE-2020-27171)

  - An out-of-bounds (OOB) memory access flaw was found in
    x25_bind in net/x25/af_x25.c in the Linux kernel. A
    bounds check failure allows a local attacker with a
    user account on the system to gain access to
    out-of-bounds memory, leading to a system crash or a
    leak of internal kernel information. The highest threat
    from this vulnerability is to confidentiality,
    integrity, as well as system
    availability.(CVE-2020-35519)

  - An issue was discovered in the Linux kernel before
    5.11.11. The netfilter subsystem allows attackers to
    cause a denial of service (panic) because
    net/netfilter/x_tables.c and
    include/linux/netfilter/x_tables.h lack a full memory
    barrier upon the assignment of a new table value, aka
    CID-175e476b8cdf.(CVE-2021-29650)

  - rtw_wx_set_scan in
    drivers/staging/rtl8188eu/os_dep/ioctl_linux.c in the
    Linux kernel through 5.11.6 allows writing beyond the
    end of the ->ssid[] array. NOTE: from the perspective
    of kernel.org releases, CVE IDs are not normally used
    for drivers/staging/* (unfinished work) however, system
    integrators may have situations in which a
    drivers/staging issue is relevant to their own customer
    base.(CVE-2021-28660)

  - An issue was discovered in the Linux kernel before 5.9.
    arch/x86/kvm/svm/sev.c allows attackers to cause a
    denial of service (soft lockup) by triggering
    destruction of a large SEV VM (which requires
    unregistering many encrypted regions), aka
    CID-7be74942f184.(CVE-2020-36311)

  - An issue was discovered in the Linux kernel before
    5.8.10. virt/kvm/kvm_main.c has a
    kvm_io_bus_unregister_dev memory leak upon a kmalloc
    failure, aka CID-f65886606c2d.(CVE-2020-36312)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2051
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9dbc5945");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28660");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(9)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-4.18.0-147.5.1.6.h451.eulerosv2r9",
        "kernel-tools-4.18.0-147.5.1.6.h451.eulerosv2r9",
        "kernel-tools-libs-4.18.0-147.5.1.6.h451.eulerosv2r9",
        "python3-perf-4.18.0-147.5.1.6.h451.eulerosv2r9"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"9", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
