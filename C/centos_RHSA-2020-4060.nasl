##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:4060 and
# CentOS Errata and Security Advisory 2020:4060 respectively.
##

include('compat.inc');

if (description)
{
  script_id(141619);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/30");

  script_cve_id(
    "CVE-2017-18551",
    "CVE-2018-20836",
    "CVE-2019-9454",
    "CVE-2019-9458",
    "CVE-2019-12614",
    "CVE-2019-15217",
    "CVE-2019-15807",
    "CVE-2019-15917",
    "CVE-2019-16231",
    "CVE-2019-16233",
    "CVE-2019-16994",
    "CVE-2019-17053",
    "CVE-2019-17055",
    "CVE-2019-18808",
    "CVE-2019-19046",
    "CVE-2019-19055",
    "CVE-2019-19058",
    "CVE-2019-19059",
    "CVE-2019-19062",
    "CVE-2019-19063",
    "CVE-2019-19332",
    "CVE-2019-19447",
    "CVE-2019-19523",
    "CVE-2019-19524",
    "CVE-2019-19530",
    "CVE-2019-19534",
    "CVE-2019-19537",
    "CVE-2019-19767",
    "CVE-2019-19807",
    "CVE-2019-20054",
    "CVE-2019-20095",
    "CVE-2019-20636",
    "CVE-2020-1749",
    "CVE-2020-2732",
    "CVE-2020-8647",
    "CVE-2020-8649",
    "CVE-2020-9383",
    "CVE-2020-10690",
    "CVE-2020-10732",
    "CVE-2020-10742",
    "CVE-2020-10751",
    "CVE-2020-10942",
    "CVE-2020-11565",
    "CVE-2020-12770",
    "CVE-2020-12826",
    "CVE-2020-14305"
  );
  script_bugtraq_id(108196, 108550);
  script_xref(name:"RHSA", value:"2020:4060");

  script_name(english:"CentOS 7 : kernel (CESA-2020:4060)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2020:4060 advisory.

  - kernel: out of bounds write in function i2c_smbus_xfer_emulated in drivers/i2c/i2c-core-smbus.c
    (CVE-2017-18551)

  - kernel: race condition in smp_task_timedout() and smp_task_done() in drivers/scsi/libsas/sas_expander.c
    leads to use-after-free (CVE-2018-20836)

  - kernel: null pointer dereference in dlpar_parse_cc_property in arch/powerrc/platforms/pseries/dlpar.c
    causing denial of service (CVE-2019-12614)

  - kernel: null pointer dereference in drivers/media/usb/zr364xx/zr364xx.c driver (CVE-2019-15217)

  - kernel: Memory leak in drivers/scsi/libsas/sas_expander.c (CVE-2019-15807)

  - kernel: use-after-free in drivers/bluetooth/hci_ldisc.c (CVE-2019-15917)

  - kernel: null-pointer dereference in drivers/net/fjes/fjes_main.c (CVE-2019-16231)

  - kernel: null pointer dereference in drivers/scsi/qla2xxx/qla_os.c (CVE-2019-16233)

  - kernel: Memory leak in sit_init_net() in net/ipv6/sit.c (CVE-2019-16994)

  - kernel: unprivileged users able to create RAW sockets in AF_IEEE802154 network protocol (CVE-2019-17053)

  - kernel: unprivileged users able to create RAW sockets in AF_ISDN network protocol (CVE-2019-17055)

  - kernel: memory leak in ccp_run_sha_cmd() function in drivers/crypto/ccp/ccp-ops.c (CVE-2019-18808)

  - kernel: Denial Of Service in the __ipmi_bmc_register() function in drivers/char/ipmi/ipmi_msghandler.c
    (CVE-2019-19046)

  - kernel: memory leak in the nl80211_get_ftm_responder_stats() function in net/wireless/nl80211.c allows DoS
    (CVE-2019-19055)

  - kernel: A memory leak in the alloc_sgtable() function in drivers/net/wireless/intel/iwlwifi/fw/dbg.c
    allows for a DoS (CVE-2019-19058)

  - kernel: Multiple memory leaks in the iwl_pcie_ctxt_info_gen3_init() function in
    drivers/net/wireless/intel/iwlwifi/pcie/ctxt-info-gen3.c allows for a DoS (CVE-2019-19059)

  - kernel: memory leak in the crypto_report() function in crypto/crypto_user_base.c allows for DoS
    (CVE-2019-19062)

  - kernel: Two memory leaks in the rtl_usb_probe() function in drivers/net/wireless/realtek/rtlwifi/usb.c
    allow for a DoS (CVE-2019-19063)

  - Kernel: kvm: OOB memory write via kvm_dev_ioctl_get_cpuid (CVE-2019-19332)

  - kernel: mounting a crafted ext4 filesystem image, performing some operations, and unmounting can lead to a
    use-after-free in ext4_put_super in fs/ext4/super.c (CVE-2019-19447)

  - kernel: use-after-free caused by a malicious USB device in the drivers/usb/misc/adutux.c driver
    (CVE-2019-19523)

  - kernel: a malicious USB device in the drivers/input/ff-memless.c leads to use-after-free (CVE-2019-19524)

  - kernel: use-after-free caused by a malicious USB device in the drivers/usb/class/cdc-acm.c driver
    (CVE-2019-19530)

  - kernel: information leak bug caused by a malicious USB device in the
    drivers/net/can/usb/peak_usb/pcan_usb_core.c driver (CVE-2019-19534)

  - kernel: race condition caused by a malicious USB device in the USB character device driver layer
    (CVE-2019-19537)

  - kernel: use-after-free in __ext4_expand_extra_isize and ext4_xattr_set_entry related to fs/ext4/inode.c
    and fs/ext4/super.c (CVE-2019-19767)

  - kernel: use-after-free in sound/core/timer.c (CVE-2019-19807)

  - kernel: Null pointer dereference in drop_sysctl_table() in fs/proc/proc_sysctl.c (CVE-2019-20054)

  - kernel: memory leak in mwifiex_tm_cmd in drivers/net/wireless/marvell/mwifiex/cfg80211.c (CVE-2019-20095)

  - kernel: out-of-bounds write via crafted keycode table (CVE-2019-20636)

  - kernel: out of bounds write in i2c driver leads to local escalation of privilege (CVE-2019-9454)

  - kernel: use after free due to race condition in the video driver leads to local privilege escalation
    (CVE-2019-9458)

  - kernel: use-after-free in cdev_put() when a PTP device is removed while it's chardev is open
    (CVE-2020-10690)

  - kernel: uninitialized kernel data leak in userspace coredumps (CVE-2020-10732)

  - kernel: NFS client crash due to index buffer overflow during Direct IO write causing kernel panic
    (CVE-2020-10742)

  - kernel: SELinux netlink permission check bypass (CVE-2020-10751)

  - kernel: vhost-net: stack overflow in get_raw_socket while checking sk_family field (CVE-2020-10942)

  - kernel: out-of-bounds write in mpol_parse_str function in mm/mempolicy.c (CVE-2020-11565)

  - kernel: sg_write function lacks an sg_remove_request call in a certain failure case (CVE-2020-12770)

  - kernel: possible to send arbitrary signals to a privileged (suidroot) parent process (CVE-2020-12826)

  - kernel: memory corruption in Voice over IP nf_conntrack_h323 module (CVE-2020-14305)

  - kernel: some ipv6 protocols not encrypted over ipsec tunnel (CVE-2020-1749)

  - Kernel: kvm: nVMX: L2 guest may trick the L0 hypervisor to access sensitive L1 resources (CVE-2020-2732)

  - kernel: out-of-bounds read in in vc_do_resize function in drivers/tty/vt/vt.c (CVE-2020-8647)

  - kernel: invalid read location in vgacon_invert_region function in drivers/video/console/vgacon.c
    (CVE-2020-8649)

  - kernel: out-of-bounds read in set_fdc in drivers/block/floppy.c (CVE-2020-9383)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-October/012745.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c5e7544c");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/20.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/94.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/119.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/121.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/125.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/200.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/250.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/319.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/349.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/362.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/400.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/401.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/416.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/476.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/772.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/787.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-20836");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20, 94, 119, 121, 125, 200, 250, 319, 349, 362, 400, 401, 416, 476, 772, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/CentOS/release');
if (isnull(release) || 'CentOS' >!< release) audit(AUDIT_OS_NOT, 'CentOS');
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'CentOS 7.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

pkgs = [
    {'reference':'bpftool-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'kernel-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'kernel-abi-whitelists-3.10.0-1160.el7', 'release':'CentOS-7'},
    {'reference':'kernel-debug-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'kernel-debug-devel-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'kernel-devel-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'kernel-headers-3.10.0-1160.el7', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'kernel-headers-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'kernel-tools-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'kernel-tools-libs-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'kernel-tools-libs-devel-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'perf-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'python-perf-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'CentOS-7'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +
    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-whitelists / etc');
}
