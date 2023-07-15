#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:1039-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159460);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/13");

  script_cve_id(
    "CVE-2021-0920",
    "CVE-2021-39657",
    "CVE-2021-39698",
    "CVE-2021-44879",
    "CVE-2021-45402",
    "CVE-2022-0487",
    "CVE-2022-0617",
    "CVE-2022-0644",
    "CVE-2022-23036",
    "CVE-2022-23037",
    "CVE-2022-23038",
    "CVE-2022-23039",
    "CVE-2022-23040",
    "CVE-2022-23041",
    "CVE-2022-23042",
    "CVE-2022-24448",
    "CVE-2022-24958",
    "CVE-2022-24959",
    "CVE-2022-25258",
    "CVE-2022-25636",
    "CVE-2022-26490",
    "CVE-2022-26966"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/13");

  script_name(english:"openSUSE 15 Security Update : kernel (openSUSE-SU-2022:1039-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:1039-1 advisory.

  - In unix_scm_to_skb of af_unix.c, there is a possible use after free bug due to a race condition. This
    could lead to local escalation of privilege with System execution privileges needed. User interaction is
    not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-196926917References:
    Upstream kernel (CVE-2021-0920)

  - In ufshcd_eh_device_reset_handler of ufshcd.c, there is a possible out of bounds read due to a missing
    bounds check. This could lead to local information disclosure with System execution privileges needed.
    User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-194696049References: Upstream kernel (CVE-2021-39657)

  - In aio_poll_complete_work of aio.c, there is a possible memory corruption due to a use after free. This
    could lead to local escalation of privilege with no additional execution privileges needed. User
    interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-185125206References: Upstream kernel (CVE-2021-39698)

  - In gc_data_segment in fs/f2fs/gc.c in the Linux kernel before 5.16.3, special files are not considered,
    leading to a move_data_page NULL pointer dereference. (CVE-2021-44879)

  - The check_alu_op() function in kernel/bpf/verifier.c in the Linux kernel through v5.16-rc5 did not
    properly update bounds while handling the mov32 instruction, which allows local users to obtain
    potentially sensitive address information, aka a pointer leak. (CVE-2021-45402)

  - A use-after-free vulnerability was found in rtsx_usb_ms_drv_remove in drivers/memstick/host/rtsx_usb_ms.c
    in memstick in the Linux kernel. In this flaw, a local attacker with a user privilege may impact system
    Confidentiality. This flaw affects kernel versions prior to 5.14 rc1. (CVE-2022-0487)

  - A flaw null pointer dereference in the Linux kernel UDF file system functionality was found in the way
    user triggers udf_file_write_iter function for the malicious UDF image. A local user could use this flaw
    to crash the system. Actual from Linux kernel 4.2-rc1 till 5.17-rc2. (CVE-2022-0617)

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

  - An issue was discovered in fs/nfs/dir.c in the Linux kernel before 5.16.5. If an application sets the
    O_DIRECTORY flag, and tries to open a regular file, nfs_atomic_open() performs a regular lookup. If a
    regular file is found, ENOTDIR should occur, but the server instead returns uninitialized data in the file
    descriptor. (CVE-2022-24448)

  - drivers/usb/gadget/legacy/inode.c in the Linux kernel through 5.16.8 mishandles dev->buf release.
    (CVE-2022-24958)

  - An issue was discovered in the Linux kernel before 5.16.5. There is a memory leak in yam_siocdevprivate in
    drivers/net/hamradio/yam.c. (CVE-2022-24959)

  - An issue was discovered in drivers/usb/gadget/composite.c in the Linux kernel before 5.16.10. The USB
    Gadget subsystem lacks certain validation of interface OS descriptor requests (ones with a large array
    index and ones associated with NULL function pointer retrieval). Memory corruption might occur.
    (CVE-2022-25258)

  - net/netfilter/nf_dup_netdev.c in the Linux kernel 5.4 through 5.6.10 allows local users to gain privileges
    because of a heap out-of-bounds write. This is related to nf_tables_offload. (CVE-2022-25636)

  - st21nfca_connectivity_event_received in drivers/nfc/st21nfca/se.c in the Linux kernel through 5.16.12 has
    EVT_TRANSACTION buffer overflows because of untrusted length parameters. (CVE-2022-26490)

  - An issue was discovered in the Linux kernel before 5.16.12. drivers/net/usb/sr9700.c allows attackers to
    obtain sensitive information from heap memory via crafted frame lengths from a device. (CVE-2022-26966)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176774");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178134");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181147");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192273");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193731");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193787");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193864");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194463");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194943");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195254");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195403");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195897");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195905");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195939");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195987");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196079");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196095");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196130");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196132");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196155");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196299");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196301");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196433");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196468");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196488");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196723");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196830");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196868");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196956");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196959");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/XWMVMDEM47CT6AQ4RWZEZZJSH2G2J4CV/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?09812907");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0920");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39657");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39698");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-44879");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-45402");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0487");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0617");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0644");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23036");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23037");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23038");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23039");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23040");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23041");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23042");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-24448");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-24958");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-24959");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-25258");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-25636");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-26490");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-26966");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39698");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-26490");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cluster-md-kmp-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cluster-md-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cluster-md-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dlm-kmp-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dlm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dlm-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-al");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-allwinner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-altera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-amd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-amlogic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-apm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-broadcom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-cavium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-exynos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-freescale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-hisilicon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-lg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-mediatek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-nvidia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-qcom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-renesas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-rockchip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-socionext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-sprd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-xilinx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtb-zte");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gfs2-kmp-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gfs2-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-64kb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-64kb-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-64kb-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-64kb-optional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base-rebuild");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-livepatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-optional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-qa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt-optional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kselftests-kmp-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kselftests-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kselftests-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ocfs2-kmp-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ocfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ocfs2-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:reiserfs-kmp-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:reiserfs-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:reiserfs-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'cluster-md-kmp-64kb-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cluster-md-kmp-default-5.3.18-150300.59.60.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cluster-md-kmp-preempt-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cluster-md-kmp-preempt-5.3.18-150300.59.60.4', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dlm-kmp-64kb-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dlm-kmp-default-5.3.18-150300.59.60.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dlm-kmp-preempt-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dlm-kmp-preempt-5.3.18-150300.59.60.4', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-al-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-allwinner-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-altera-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-amd-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-amlogic-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-apm-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-arm-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-broadcom-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-cavium-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-exynos-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-freescale-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-hisilicon-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-lg-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-marvell-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-mediatek-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-nvidia-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-qcom-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-renesas-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-rockchip-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-socionext-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-sprd-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-xilinx-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dtb-zte-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gfs2-kmp-64kb-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gfs2-kmp-default-5.3.18-150300.59.60.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gfs2-kmp-preempt-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gfs2-kmp-preempt-5.3.18-150300.59.60.4', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64kb-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64kb-devel-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64kb-extra-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64kb-livepatch-devel-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64kb-optional-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-5.3.18-150300.59.60.4', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-5.3.18-150300.59.60.4', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-livepatch-devel-5.3.18-150300.59.60.4', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-5.3.18-150300.59.60.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-base-5.3.18-150300.59.60.4.150300.18.37.5', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-base-rebuild-5.3.18-150300.59.60.4.150300.18.37.5', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-devel-5.3.18-150300.59.60.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-extra-5.3.18-150300.59.60.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-livepatch-5.3.18-150300.59.60.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-livepatch-devel-5.3.18-150300.59.60.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-optional-5.3.18-150300.59.60.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-5.3.18-150300.59.60.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-kvmsmall-5.3.18-150300.59.60.4', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-kvmsmall-devel-5.3.18-150300.59.60.4', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-kvmsmall-livepatch-devel-5.3.18-150300.59.60.4', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-macros-5.3.18-150300.59.60.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-obs-build-5.3.18-150300.59.60.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-obs-qa-5.3.18-150300.59.60.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-5.3.18-150300.59.60.4', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-devel-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-devel-5.3.18-150300.59.60.4', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-extra-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-extra-5.3.18-150300.59.60.4', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-livepatch-devel-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-livepatch-devel-5.3.18-150300.59.60.4', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-optional-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-optional-5.3.18-150300.59.60.4', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-source-5.3.18-150300.59.60.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-source-vanilla-5.3.18-150300.59.60.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-syms-5.3.18-150300.59.60.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-5.3.18-150300.59.60.4', 'cpu':'s390x', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kselftests-kmp-64kb-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kselftests-kmp-default-5.3.18-150300.59.60.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kselftests-kmp-preempt-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kselftests-kmp-preempt-5.3.18-150300.59.60.4', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-kmp-64kb-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-kmp-default-5.3.18-150300.59.60.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-kmp-preempt-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-kmp-preempt-5.3.18-150300.59.60.4', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'reiserfs-kmp-64kb-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'reiserfs-kmp-default-5.3.18-150300.59.60.4', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'reiserfs-kmp-preempt-5.3.18-150300.59.60.4', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'reiserfs-kmp-preempt-5.3.18-150300.59.60.4', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-64kb / cluster-md-kmp-default / cluster-md-kmp-preempt / etc');
}
