#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-5866.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(141207);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/08");

  script_cve_id(
    "CVE-2016-10905",
    "CVE-2016-10906",
    "CVE-2017-8924",
    "CVE-2017-8925",
    "CVE-2017-16528",
    "CVE-2018-9415",
    "CVE-2018-16884",
    "CVE-2018-20856",
    "CVE-2019-3846",
    "CVE-2019-3874",
    "CVE-2019-5108",
    "CVE-2019-6974",
    "CVE-2019-7221",
    "CVE-2019-7222",
    "CVE-2019-11487",
    "CVE-2019-14898",
    "CVE-2019-15218",
    "CVE-2019-15505",
    "CVE-2019-15927",
    "CVE-2019-16746",
    "CVE-2019-17075",
    "CVE-2019-18885",
    "CVE-2019-19052",
    "CVE-2019-19073",
    "CVE-2019-19768",
    "CVE-2019-19965",
    "CVE-2019-20054",
    "CVE-2019-20096",
    "CVE-2019-20812",
    "CVE-2020-1749",
    "CVE-2020-10720",
    "CVE-2020-10751",
    "CVE-2020-10769",
    "CVE-2020-14314",
    "CVE-2020-14331",
    "CVE-2020-25212",
    "CVE-2020-25284",
    "CVE-2020-25285"
  );
  script_bugtraq_id(
    98451,
    98462,
    106253,
    106963,
    107127,
    107294,
    107488,
    108054,
    108521
  );

  script_name(english:"Oracle Linux 6 / 7 : Unbreakable Enterprise kernel (ELSA-2020-5866)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 / 7 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2020-5866 advisory.

  - In the Linux kernel before 4.20.8, kvm_ioctl_create_device in virt/kvm/kvm_main.c mishandles reference
    counting because of a race condition, leading to a use-after-free. (CVE-2019-6974)

  - The KVM implementation in the Linux kernel through 4.20.5 has a Use-after-Free. (CVE-2019-7221)

  - The KVM implementation in the Linux kernel through 4.20.5 has an Information Leak. (CVE-2019-7222)

  - A flaw was found in the Linux kernel's NFS41+ subsystem. NFS41+ shares mounted in different network
    namespaces at the same time can make bc_svc_process() use wrong back-channel IDs and cause a use-after-
    free vulnerability. Thus a malicious container user can cause a host kernel memory corruption and a system
    panic. Due to the nature of the flaw, privilege escalation cannot be fully ruled out. (CVE-2018-16884)

  - A flaw that allowed an attacker to corrupt memory and possibly escalate privileges was found in the
    mwifiex kernel module while connecting to a malicious wireless network. (CVE-2019-3846)

  - The Linux kernel before 5.1-rc5 allows page->_refcount reference count overflow, with resultant use-after-
    free issues, if about 140 GiB of RAM exists. This is related to fs/fuse/dev.c, fs/pipe.c, fs/splice.c,
    include/linux/mm.h, include/linux/pipe_fs_i.h, kernel/trace/trace.c, mm/gup.c, and mm/hugetlb.c. It can
    occur with FUSE requests. (CVE-2019-11487)

  - An issue was discovered in the Linux kernel before 4.18.7. In block/blk-core.c, there is an
    __blk_drain_queue() use-after-free because a certain error case is mishandled. (CVE-2018-20856)

  - The SCTP socket buffer used by a userspace application is not accounted by the cgroups subsystem. An
    attacker can use this flaw to cause a denial of service attack. Kernel 3.10.x and 4.18.x branches are
    believed to be vulnerable. (CVE-2019-3874)

  - The fix for CVE-2019-11599, affecting the Linux kernel before 5.0.10 was not complete. A local user could
    use this flaw to obtain sensitive information, cause a denial of service, or possibly have other
    unspecified impacts by triggering a race condition with mmget_not_zero or get_task_mm calls.
    (CVE-2019-14898)

  - In the Linux kernel before 5.0.6, there is a NULL pointer dereference in drop_sysctl_table() in
    fs/proc/proc_sysctl.c, related to put_links, aka CID-23da9588037e. (CVE-2019-20054)

  - An issue was discovered in net/wireless/nl80211.c in the Linux kernel through 5.2.17. It does not check
    the length of variable elements in a beacon head, leading to a buffer overflow. (CVE-2019-16746)

  - In the Linux kernel 5.4.0-rc2, there is a use-after-free (read) in the __blk_add_trace function in
    kernel/trace/blktrace.c (which is used to fill out a blk_io_trace structure and place it in a per-cpu sub-
    buffer). (CVE-2019-19768)

  - In the Linux kernel through 5.4.6, there is a NULL pointer dereference in
    drivers/scsi/libsas/sas_discover.c because of mishandling of port disconnection during discovery, related
    to a PHY down race condition, aka CID-f70267f379b5. (CVE-2019-19965)

  - In the Linux kernel before 5.1, there is a memory leak in __feat_register_sp() in net/dccp/feat.c, which
    may cause denial of service, aka CID-1d3ff0950e2b. (CVE-2019-20096)

  - A flaw was found in the Linux kernel's implementation of some networking protocols in IPsec, such as VXLAN
    and GENEVE tunnels over IPv6. When an encrypted tunnel is created between two hosts, the kernel isn't
    correctly routing tunneled data over the encrypted link; rather sending the data unencrypted. This would
    allow anyone in between the two endpoints to read the traffic unencrypted. The main threat from this
    vulnerability is to data confidentiality. (CVE-2020-1749)

  - Memory leaks in drivers/net/wireless/ath/ath9k/htc_hst.c in the Linux kernel through 5.3.11 allow
    attackers to cause a denial of service (memory consumption) by triggering wait_for_completion_timeout()
    failures. This affects the htc_config_pipe_credits() function, the htc_setup_complete() function, and the
    htc_connect_service() function, aka CID-853acf7caf10. (CVE-2019-19073)

  - drivers/media/usb/dvb-usb/technisat-usb2.c in the Linux kernel through 5.2.9 has an out-of-bounds read via
    crafted USB device traffic (which may be remote via usbip or usbredir). (CVE-2019-15505)

  - An issue was discovered in the Linux kernel before 5.4.7. The prb_calc_retire_blk_tmo() function in
    net/packet/af_packet.c can result in a denial of service (CPU consumption and soft lockup) in a certain
    failure case involving TPACKET_V3, aka CID-b43d1f9f7067. (CVE-2019-20812)

  - A flaw was found in the Linux kernels implementation of the invert video code on VGA consoles when a
    local attacker attempts to resize the console, calling an ioctl VT_RESIZE, which causes an out-of-bounds
    write to occur. This flaw allows a local user with access to the VGA console to crash the system,
    potentially escalating their privileges on the system. The highest threat from this vulnerability is to
    data confidentiality and integrity as well as system availability. (CVE-2020-14331)

  - fs/btrfs/volumes.c in the Linux kernel before 5.1 allows a btrfs_verify_dev_extents NULL pointer
    dereference via a crafted btrfs image because fs_devices->devices is mishandled within find_device, aka
    CID-09ba3bc9dd15. (CVE-2019-18885)

  - A buffer over-read flaw was found in RH kernel versions before 5.0 in crypto_authenc_extractkeys in
    crypto/authenc.c in the IPsec Cryptographic algorithm's module, authenc. When a payload longer than 4
    bytes, and is not following 4-byte alignment boundary guidelines, it causes a buffer over-read threat,
    leading to a system crash. This flaw allows a local attacker with user privileges to cause a denial of
    service. (CVE-2020-10769)

  - A flaw was found in the Linux kernels SELinux LSM hook implementation before version 5.7, where it
    incorrectly assumed that an skb would only contain a single netlink message. The hook would incorrectly
    only validate the first netlink message in the skb and allow or deny the rest of the messages within the
    skb with the granted permission without further processing. (CVE-2020-10751)

  - An exploitable denial-of-service vulnerability exists in the Linux kernel prior to mainline 5.3. An
    attacker could exploit this vulnerability by triggering AP to send IAPP location updates for stations
    before the required authentication process has completed. This could lead to different denial-of-service
    scenarios, either by causing CAM table attacks, or by leading to traffic flapping if faking already
    existing clients in other nearby APs of the same wireless infrastructure. An attacker can forge
    Authentication and Association Request packets to trigger this vulnerability. (CVE-2019-5108)

  - An issue was discovered in write_tpt_entry in drivers/infiniband/hw/cxgb4/mem.c in the Linux kernel
    through 5.3.2. The cxgb4 driver is directly calling dma_map_single (a DMA function) from a stack variable.
    This could allow an attacker to trigger a Denial of Service, exploitable if this driver is used on an
    architecture for which this stack/DMA interaction has security relevance. (CVE-2019-17075)

  - An issue was discovered in the Linux kernel before 5.1.8. There is a NULL pointer dereference caused by a
    malicious USB device in the drivers/media/usb/siano/smsusb.c driver. (CVE-2019-15218)

  - A memory leak in the gs_can_open() function in drivers/net/can/usb/gs_usb.c in the Linux kernel before
    5.3.11 allows attackers to cause a denial of service (memory consumption) by triggering usb_submit_urb()
    failures, aka CID-fb5be6a7b486. (CVE-2019-19052)

  - An issue was discovered in fs/gfs2/rgrp.c in the Linux kernel before 4.8. A use-after-free is caused by
    the functions gfs2_clear_rgrpd and read_rindex_entry. (CVE-2016-10905)

  - An issue was discovered in drivers/net/ethernet/arc/emac_main.c in the Linux kernel before 4.5. A use-
    after-free is caused by a race condition between the functions arc_emac_tx and arc_emac_tx_clean.
    (CVE-2016-10906)

  - The omninet_open function in drivers/usb/serial/omninet.c in the Linux kernel before 4.10.4 allows local
    users to cause a denial of service (tty exhaustion) by leveraging reference count mishandling.
    (CVE-2017-8925)

  - A memory out-of-bounds read flaw was found in the Linux kernel before 5.9-rc2 with the ext3/ext4 file
    system, in the way it accesses a directory with broken indexing. This flaw allows a local user to crash
    the system if the directory exists. The highest threat from this vulnerability is to system availability.
    (CVE-2020-14314)

  - sound/core/seq_device.c in the Linux kernel before 4.13.4 allows local users to cause a denial of service
    (snd_rawmidi_dev_seq_free use-after-free and system crash) or possibly have unspecified other impact via a
    crafted USB device. (CVE-2017-16528)

  - The edge_bulk_in_callback function in drivers/usb/serial/io_ti.c in the Linux kernel before 4.10.4 allows
    local users to obtain sensitive information (in the dmesg ringbuffer and syslog) from uninitialized kernel
    memory by using a crafted USB device (posing as an io_ti USB serial device) to trigger an integer
    underflow. (CVE-2017-8924)

  - In driver_override_store and driver_override_show of bus.c, there is a possible double free due to
    improper locking. This could lead to local escalation of privilege with System execution privileges
    needed. User interaction is not needed for exploitation. Product: Android Versions: Android kernel Android
    ID: A-69129004 References: Upstream kernel. (CVE-2018-9415)

  - An issue was discovered in the Linux kernel before 4.20.2. An out-of-bounds access exists in the function
    build_audio_procunit in the file sound/usb/mixer.c. (CVE-2019-15927)

  - A flaw was found in the Linux kernel's implementation of GRO in versions before 5.2. This flaw allows an
    attacker with local access to crash the system. (CVE-2020-10720)

  - A TOCTOU mismatch in the NFS client code in the Linux kernel before 5.8.3 could be used by local attackers
    to corrupt memory or possibly have unspecified other impact because a size check is in fs/nfs/nfs4proc.c
    instead of fs/nfs/nfs4xdr.c, aka CID-b4487b935452. (CVE-2020-25212)

  - The rbd block device driver in drivers/block/rbd.c in the Linux kernel through 5.8.9 used incomplete
    permission checking for access to rbd devices, which could be leveraged by local attackers to map or unmap
    rbd block devices, aka CID-f44d04e696fe. (CVE-2020-25284)

  - A race condition between hugetlb sysctl handlers in mm/hugetlb.c in the Linux kernel before 5.8.8 could be
    used by local attackers to corrupt memory, cause a NULL pointer dereference, or possibly have unspecified
    other impact, aka CID-17743798d812. (CVE-2020-25285)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2020-5866.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15505");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("linux_alt_patch_detect.nasl", "ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('ksplice.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 6 / 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['4.1.12-124.43.4.el6uek', '4.1.12-124.43.4.el7uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2020-5866');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '4.1';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'kernel-uek-4.1.12-124.43.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.1.12'},
    {'reference':'kernel-uek-debug-4.1.12-124.43.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-4.1.12'},
    {'reference':'kernel-uek-debug-devel-4.1.12-124.43.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-4.1.12'},
    {'reference':'kernel-uek-devel-4.1.12-124.43.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-4.1.12'},
    {'reference':'kernel-uek-doc-4.1.12-124.43.4.el6uek', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-4.1.12'},
    {'reference':'kernel-uek-firmware-4.1.12-124.43.4.el6uek', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-4.1.12'},
    {'reference':'kernel-uek-4.1.12-124.43.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.1.12'},
    {'reference':'kernel-uek-debug-4.1.12-124.43.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-4.1.12'},
    {'reference':'kernel-uek-debug-devel-4.1.12-124.43.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-4.1.12'},
    {'reference':'kernel-uek-devel-4.1.12-124.43.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-4.1.12'},
    {'reference':'kernel-uek-doc-4.1.12-124.43.4.el7uek', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-4.1.12'},
    {'reference':'kernel-uek-firmware-4.1.12-124.43.4.el7uek', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-4.1.12'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release) {
    if (exists_check) {
        if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-uek / kernel-uek-debug / kernel-uek-debug-devel / etc');
}
