#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:1038-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159353);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/13");

  script_cve_id(
    "CVE-2021-0920",
    "CVE-2021-39698",
    "CVE-2021-44879",
    "CVE-2021-45402",
    "CVE-2022-0487",
    "CVE-2022-0492",
    "CVE-2022-0516",
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
    "CVE-2022-26966",
    "CVE-2022-27223"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:1038-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/13");

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2022:1038-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:1038-1 advisory.

  - In unix_scm_to_skb of af_unix.c, there is a possible use after free bug due to a race condition. This
    could lead to local escalation of privilege with System execution privileges needed. User interaction is
    not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-196926917References:
    Upstream kernel (CVE-2021-0920)

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

  - A vulnerability was found in the Linux kernel's cgroup_release_agent_write in the
    kernel/cgroup/cgroup-v1.c function. This flaw, under certain circumstances, allows the use of the cgroups
    v1 release_agent feature to escalate privileges and bypass the namespace isolation unexpectedly.
    (CVE-2022-0492)

  - A vulnerability was found in kvm_s390_guest_sida_op in the arch/s390/kvm/kvm-s390.c function in KVM for
    s390 in the Linux kernel. This flaw allows a local attacker with a normal user privilege to obtain
    unauthorized memory write access. This flaw affects Linux kernel versions prior to 5.17-rc4.
    (CVE-2022-0516)

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

  - In drivers/usb/gadget/udc/udc-xilinx.c in the Linux kernel before 5.16.12, the endpoint index is not
    validated and might be manipulated by the host for out-of-array access. (CVE-2022-27223)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/922815");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/998635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176774");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178134");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181147");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192273");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193787");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194943");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195403");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195897");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195908");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195947");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195987");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196079");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196095");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196130");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196155");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196299");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196301");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196403");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196468");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196488");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196723");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196776");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196830");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196868");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197300");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-March/010567.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?96e50616");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0920");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39698");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-44879");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-45402");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0487");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0492");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0516");
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
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-27223");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39698");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-27223");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt_debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

var sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP3", os_ver + " SP" + sp);

var pkgs = [
    {'reference':'cluster-md-kmp-rt-5.3.18-150300.82.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_RT-release-15.3'},
    {'reference':'dlm-kmp-rt-5.3.18-150300.82.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_RT-release-15.3'},
    {'reference':'gfs2-kmp-rt-5.3.18-150300.82.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_RT-release-15.3'},
    {'reference':'kernel-devel-rt-5.3.18-150300.82.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_RT-release-15.3'},
    {'reference':'kernel-rt-5.3.18-150300.82.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_RT-release-15.3'},
    {'reference':'kernel-rt-devel-5.3.18-150300.82.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_RT-release-15.3'},
    {'reference':'kernel-rt_debug-devel-5.3.18-150300.82.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_RT-release-15.3'},
    {'reference':'kernel-source-rt-5.3.18-150300.82.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_RT-release-15.3'},
    {'reference':'kernel-syms-rt-5.3.18-150300.82.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_RT-release-15.3'},
    {'reference':'ocfs2-kmp-rt-5.3.18-150300.82.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_RT-release-15.3'},
    {'reference':'cluster-md-kmp-rt-5.3.18-150300.82.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.3'},
    {'reference':'dlm-kmp-rt-5.3.18-150300.82.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.3'},
    {'reference':'gfs2-kmp-rt-5.3.18-150300.82.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.3'},
    {'reference':'kernel-devel-rt-5.3.18-150300.82.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.3'},
    {'reference':'kernel-rt-5.3.18-150300.82.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.3'},
    {'reference':'kernel-rt-devel-5.3.18-150300.82.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.3'},
    {'reference':'kernel-rt_debug-devel-5.3.18-150300.82.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.3'},
    {'reference':'kernel-source-rt-5.3.18-150300.82.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.3'},
    {'reference':'kernel-syms-rt-5.3.18-150300.82.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.3'},
    {'reference':'ocfs2-kmp-rt-5.3.18-150300.82.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.3'}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (exists_check) {
      if (!rpm_exists(release:release, rpm:exists_check)) continue;
      if ('ltss' >< tolower(exists_check)) ltss_caveat_required = TRUE;
    }
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-rt / dlm-kmp-rt / gfs2-kmp-rt / kernel-devel-rt / etc');
}
