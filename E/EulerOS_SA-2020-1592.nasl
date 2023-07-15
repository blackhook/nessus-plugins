#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(136870);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id(
    "CVE-2019-19377",
    "CVE-2019-19462",
    "CVE-2020-10711",
    "CVE-2020-10720",
    "CVE-2020-10942",
    "CVE-2020-11884",
    "CVE-2020-12114",
    "CVE-2020-12464",
    "CVE-2020-12465",
    "CVE-2020-12652",
    "CVE-2020-12653",
    "CVE-2020-12654",
    "CVE-2020-12655",
    "CVE-2020-12656",
    "CVE-2020-12657",
    "CVE-2020-12659",
    "CVE-2020-12769",
    "CVE-2020-12770",
    "CVE-2020-12771",
    "CVE-2020-12826"
  );

  script_name(english:"EulerOS 2.0 SP8 : kernel (EulerOS-SA-2020-1592)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A flaw was found in the Linux kernel's implementation
    of GRO. This flaw allows an attacker with local access
    to crash the system.(CVE-2020-10720)

  - A NULL pointer dereference flaw was found in the Linux
    kernel's SELinux subsystem. This flaw occurs while
    importing the Commercial IP Security Option (CIPSO)
    protocol's category bitmap into the SELinux extensible
    bitmap via the' ebitmap_netlbl_import' routine. While
    processing the CIPSO restricted bitmap tag in the
    'cipso_v4_parsetag_rbm' routine, it sets the security
    attribute to indicate that the category bitmap is
    present, even if it has not been allocated. This issue
    leads to a NULL pointer dereference issue while
    importing the same category bitmap into SELinux. This
    flaw allows a remote network user to crash the system
    kernel, resulting in a denial of
    service.(CVE-2020-10711)

  - A signal access-control issue was discovered in the
    Linux kernel before 5.6.5, aka CID-7395ea4e65c2.
    Because exec_id in include/linux/sched.h is only 32
    bits, an integer overflow can interfere with a
    do_notify_parent protection mechanism. A child process
    can send an arbitrary signal to a parent process in a
    different security domain. Exploitation limitations
    include the amount of elapsed time before an integer
    overflow occurs, and the lack of scenarios where
    signals to a parent process present a substantial
    operational threat.(CVE-2020-12826)

  - An issue was discovered in the Linux kernel before
    5.4.17. drivers/spi/spi-dw.c allows attackers to cause
    a panic via concurrent calls to dw_spi_irq and
    dw_spi_transfer_one, aka
    CID-19b61392c5a8.(CVE-2020-12769)

  - An issue was discovered in the Linux kernel through
    5.6.11. sg_write lacks an sg_remove_request call in a
    certain failure case, aka
    CID-83c6f2390040.(CVE-2020-12770)

  - An issue was discovered in the Linux kernel through
    5.6.11. btree_gc_coalesce in drivers/md/bcache/btree.c
    has a deadlock if a coalescing operation
    fails.(CVE-2020-12771)

  - The __mptctl_ioctl function in
    drivers/message/fusion/mptctl.c in the Linux kernel
    before 5.4.14 allows local users to hold an incorrect
    lock during the ioctl operation and trigger a race
    condition, i.e., a 'double fetch' vulnerability, aka
    CID-28d76df18f0a. NOTE: the vendor states 'The security
    impact of this bug is not as bad as it could have been
    because these operations are all privileged and root
    already has enormous destructive
    power.'(CVE-2020-12652)

  - An issue was discovered in xfs_agf_verify in
    fs/xfs/libxfs/xfs_alloc.c in the Linux kernel through
    5.6.10. Attackers may trigger a sync of excessive
    duration via an XFS v5 image with crafted metadata, aka
    CID-d0c7feaf8767.(CVE-2020-12655)

  - A pivot_root race condition in fs amespace.c in the
    Linux kernel 4.4.x before 4.4.221, 4.9.x before
    4.9.221, 4.14.x before 4.14.178, 4.19.x before
    4.19.119, and 5.x before 5.3 allows local users to
    cause a denial of service (panic) by corrupting a
    mountpoint reference counter.(CVE-2020-12114)

  - An issue was discovered in the Linux kernel before
    5.6.5. There is a use-after-free in block/bfq-iosched.c
    related to bfq_idle_slice_timer_body.(CVE-2020-12657)

  - usb_sg_cancel in drivers/usb/core/message.c in the
    Linux kernel before 5.6.8 has a use-after-free because
    a transfer occurs without a reference, aka
    CID-056ad39ee925.(CVE-2020-12464)

  - An issue was found in Linux kernel before 5.5.4. The
    mwifiex_cmd_append_vsie_tlv() function in drivers
    et/wireless/marvell/mwifiex/scan.c allows local users
    to gain privileges or cause a denial of service because
    of an incorrect memcpy and buffer overflow, aka
    CID-b70261a288ea.(CVE-2020-12653)

  - gss_mech_free in net/sunrpc/auth_gss/gss_mech_switch.c
    in the rpcsec_gss_krb5 implementation in the Linux
    kernel through 5.6.10 lacks certain domain_release
    calls, leading to a memory leak.(CVE-2020-12656)

  - An issue was discovered in the Linux kernel before
    5.6.7. xdp_umem_reg in net/xdp/xdp_umem.c has an
    out-of-bounds write (by a user with the CAP_NET_ADMIN
    capability) because of a lack of headroom
    validation.(CVE-2020-12659)

  - An array overflow was discovered in mt76_add_fragment
    in drivers et/wireless/mediatek/mt76/dma.c in the Linux
    kernel before 5.5.10, aka CID-b102f0c522cf. An
    oversized packet with too many rx fragments can corrupt
    memory of adjacent pages.(CVE-2020-12465)

  - An issue was found in Linux kernel before 5.5.4.
    mwifiex_ret_wmm_get_status() in drivers
    et/wireless/marvell/mwifiex/wmm.c allows a remote AP to
    trigger a heap-based buffer overflow because of an
    incorrect memcpy, aka CID-3a9b153c5591.(CVE-2020-12654)

  - In the Linux kernel through 5.6.7 on the s390 platform,
    code execution may occur because of a race condition,
    as demonstrated by code in enable_sacf_uaccess in
    arch/s390/lib/uaccess.c that fails to protect against a
    concurrent page table upgrade, aka CID-3f777e19d171. A
    crash could also occur.(CVE-2020-11884)

  - relay_open in kernel/relay.c in the Linux kernel
    through 5.4.1 allows local users to cause a denial of
    service (such as relay blockage) by triggering a NULL
    alloc_percpu result.(CVE-2019-19462)

  - In the Linux kernel 5.0.21, mounting a crafted btrfs
    filesystem image, performing some operations, and
    unmounting can lead to a use-after-free in
    btrfs_queue_work in
    fs/btrfs/async-thread.c.(CVE-2019-19377)

  - In the Linux kernel before 5.5.8, get_raw_socket in
    drivers/vhost et.c lacks validation of an sk_family
    field, which might allow attackers to trigger kernel
    stack corruption via crafted system
    calls.(CVE-2020-10942)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1592
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?966bca8a");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12659");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-12657");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["bpftool-4.19.36-vhulk1907.1.0.h748.eulerosv2r8",
        "kernel-4.19.36-vhulk1907.1.0.h748.eulerosv2r8",
        "kernel-devel-4.19.36-vhulk1907.1.0.h748.eulerosv2r8",
        "kernel-headers-4.19.36-vhulk1907.1.0.h748.eulerosv2r8",
        "kernel-source-4.19.36-vhulk1907.1.0.h748.eulerosv2r8",
        "kernel-tools-4.19.36-vhulk1907.1.0.h748.eulerosv2r8",
        "kernel-tools-libs-4.19.36-vhulk1907.1.0.h748.eulerosv2r8",
        "perf-4.19.36-vhulk1907.1.0.h748.eulerosv2r8",
        "python-perf-4.19.36-vhulk1907.1.0.h748.eulerosv2r8",
        "python3-perf-4.19.36-vhulk1907.1.0.h748.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
