##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2020:4431. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145806);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2019-9455",
    "CVE-2019-9458",
    "CVE-2019-12614",
    "CVE-2019-15917",
    "CVE-2019-15925",
    "CVE-2019-16231",
    "CVE-2019-16233",
    "CVE-2019-18808",
    "CVE-2019-18809",
    "CVE-2019-19046",
    "CVE-2019-19056",
    "CVE-2019-19062",
    "CVE-2019-19063",
    "CVE-2019-19068",
    "CVE-2019-19072",
    "CVE-2019-19319",
    "CVE-2019-19332",
    "CVE-2019-19447",
    "CVE-2019-19524",
    "CVE-2019-19533",
    "CVE-2019-19537",
    "CVE-2019-19543",
    "CVE-2019-19767",
    "CVE-2019-19770",
    "CVE-2019-20054",
    "CVE-2019-20636",
    "CVE-2020-0305",
    "CVE-2020-8647",
    "CVE-2020-8648",
    "CVE-2020-8649",
    "CVE-2020-10732",
    "CVE-2020-10751",
    "CVE-2020-10773",
    "CVE-2020-10774",
    "CVE-2020-10942",
    "CVE-2020-11565",
    "CVE-2020-11668",
    "CVE-2020-12465",
    "CVE-2020-12655",
    "CVE-2020-12659",
    "CVE-2020-12770",
    "CVE-2020-12826",
    "CVE-2020-14381",
    "CVE-2020-25641"
  );
  script_bugtraq_id(108550);
  script_xref(name:"RHSA", value:"2020:4431");

  script_name(english:"CentOS 8 : kernel (CESA-2020:4431)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2020:4431 advisory.

  - kernel: null pointer dereference in dlpar_parse_cc_property in arch/powerrc/platforms/pseries/dlpar.c
    causing denial of service (CVE-2019-12614)

  - kernel: use-after-free in drivers/bluetooth/hci_ldisc.c (CVE-2019-15917)

  - kernel: out-of-bounds access in function hclge_tm_schd_mode_vnet_base_cfg (CVE-2019-15925)

  - kernel: null-pointer dereference in drivers/net/fjes/fjes_main.c (CVE-2019-16231)

  - kernel: null pointer dereference in drivers/scsi/qla2xxx/qla_os.c (CVE-2019-16233)

  - kernel: memory leak in ccp_run_sha_cmd() function in drivers/crypto/ccp/ccp-ops.c (CVE-2019-18808)

  - kernel: memory leak in  af9005_identify_state() function in drivers/media/usb/dvb-usb/af9005.c
    (CVE-2019-18809)

  - kernel: Denial Of Service in the __ipmi_bmc_register() function in drivers/char/ipmi/ipmi_msghandler.c
    (CVE-2019-19046)

  - kernel: A memory leak in the mwifiex_pcie_alloc_cmdrsp_buf() function in
    drivers/net/wireless/marvell/mwifiex/pcie.c allows to cause DoS (CVE-2019-19056)

  - kernel: memory leak in the crypto_report() function in crypto/crypto_user_base.c allows for DoS
    (CVE-2019-19062)

  - kernel: Two memory leaks in the rtl_usb_probe() function in drivers/net/wireless/realtek/rtlwifi/usb.c
    allow for a DoS (CVE-2019-19063)

  - kernel: A memory leak in the rtl8xxxu_submit_int_urb() function in
    drivers/net/wireless/realtek/rtl8xxxu/rtl8xxxu_core.c allows for a DoS (CVE-2019-19068)

  - kernel: A memory leak in the predicate_parse() function in kernel/trace/trace_events_filter.c allows for a
    DoS (CVE-2019-19072)

  - kernel: out-of-bounds write in ext4_xattr_set_entry in fs/ext4/xattr.c (CVE-2019-19319)

  - Kernel: kvm: OOB memory write via kvm_dev_ioctl_get_cpuid (CVE-2019-19332)

  - kernel: mounting a crafted ext4 filesystem image, performing some operations, and unmounting can lead to a
    use-after-free in ext4_put_super in fs/ext4/super.c (CVE-2019-19447)

  - kernel: a malicious USB device in the drivers/input/ff-memless.c leads to use-after-free (CVE-2019-19524)

  - kernel: information leak bug caused  by a malicious USB device in the drivers/media/usb/ttusb-
    dec/ttusb_dec.c (CVE-2019-19533)

  - kernel: race condition caused by a malicious USB device in the USB character device driver layer
    (CVE-2019-19537)

  - kernel: use-after-free in serial_ir_init_module() in drivers/media/rc/serial_ir.c (CVE-2019-19543)

  - kernel: use-after-free in __ext4_expand_extra_isize and ext4_xattr_set_entry related to fs/ext4/inode.c
    and fs/ext4/super.c (CVE-2019-19767)

  - kernel: use-after-free in debugfs_remove in fs/debugfs/inode.c (CVE-2019-19770)

  - kernel: Null pointer dereference in drop_sysctl_table() in fs/proc/proc_sysctl.c (CVE-2019-20054)

  - kernel: out-of-bounds write via crafted keycode table (CVE-2019-20636)

  - kernel: kernel pointer leak due to WARN_ON statement in video driver leads to local information disclosure
    (CVE-2019-9455)

  - kernel: use after free due to race condition in the video driver leads to local privilege escalation
    (CVE-2019-9458)

  - kernel: possible use-after-free due to a race condition in cdev_get of char_dev.c (CVE-2020-0305)

  - kernel: uninitialized kernel data leak in userspace coredumps (CVE-2020-10732)

  - kernel: SELinux netlink permission check bypass (CVE-2020-10751)

  - kernel: kernel stack information leak on s390/s390x (CVE-2020-10773)

  - kernel: possibility of memory disclosure when reading the file /proc/sys/kernel/rh_features
    (CVE-2020-10774)

  - kernel: vhost-net: stack overflow in get_raw_socket while checking sk_family field (CVE-2020-10942)

  - kernel: out-of-bounds write in mpol_parse_str function in mm/mempolicy.c (CVE-2020-11565)

  - kernel: mishandles invalid descriptors in drivers/media/usb/gspca/xirlink_cit.c (CVE-2020-11668)

  - kernel: buffer overflow in mt76_add_fragment function in drivers/net/wireless/mediatek/mt76/dma.c
    (CVE-2020-12465)

  - kernel: sync of excessive duration via an XFS v5 image with crafted metadata (CVE-2020-12655)

  - kernel: xdp_umem_reg in net/xdp/xdp_umem.c has an out-of-bounds write which could result in crash and data
    coruption (CVE-2020-12659)

  - kernel: sg_write function lacks an sg_remove_request call in a certain failure case (CVE-2020-12770)

  - kernel: possible to send arbitrary signals to a privileged (suidroot) parent process (CVE-2020-12826)

  - kernel: referencing inode of removed superblock in get_futex_key() causes UAF (CVE-2020-14381)

  - kernel: soft-lockups in iov_iter_copy_from_user_atomic() could result in DoS (CVE-2020-25641)

  - kernel: out-of-bounds read in in vc_do_resize function in drivers/tty/vt/vt.c (CVE-2020-8647)

  - kernel: use-after-free in n_tty_receive_buf_common function in drivers/tty/n_tty.c (CVE-2020-8648)

  - kernel: invalid read location in vgacon_invert_region function in drivers/video/console/vgacon.c
    (CVE-2020-8649)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:4431");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12659");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-19770");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-perf");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');
include('rhel.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/CentOS/release');
if (isnull(release) || 'CentOS' >!< release) audit(AUDIT_OS_NOT, 'CentOS');
os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if ('CentOS Stream' >< release) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS Stream ' + os_ver);
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  cve_list = make_list('CVE-2019-9455', 'CVE-2019-9458', 'CVE-2019-12614', 'CVE-2019-15917', 'CVE-2019-15925', 'CVE-2019-16231', 'CVE-2019-16233', 'CVE-2019-18808', 'CVE-2019-18809', 'CVE-2019-19046', 'CVE-2019-19056', 'CVE-2019-19062', 'CVE-2019-19063', 'CVE-2019-19068', 'CVE-2019-19072', 'CVE-2019-19319', 'CVE-2019-19332', 'CVE-2019-19447', 'CVE-2019-19524', 'CVE-2019-19533', 'CVE-2019-19537', 'CVE-2019-19543', 'CVE-2019-19767', 'CVE-2019-19770', 'CVE-2019-20054', 'CVE-2019-20636', 'CVE-2020-0305', 'CVE-2020-8647', 'CVE-2020-8648', 'CVE-2020-8649', 'CVE-2020-10732', 'CVE-2020-10751', 'CVE-2020-10773', 'CVE-2020-10774', 'CVE-2020-10942', 'CVE-2020-11565', 'CVE-2020-11668', 'CVE-2020-12465', 'CVE-2020-12655', 'CVE-2020-12659', 'CVE-2020-12770', 'CVE-2020-12826', 'CVE-2020-14381', 'CVE-2020-25641');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for CESA-2020:4431');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

pkgs = [
    {'reference':'bpftool-4.18.0-240.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-4.18.0-240.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-abi-whitelists-4.18.0-240.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-abi-whitelists-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-core-4.18.0-240.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-core-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-cross-headers-4.18.0-240.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-cross-headers-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-4.18.0-240.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-core-4.18.0-240.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-core-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-4.18.0-240.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-4.18.0-240.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-extra-4.18.0-240.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-extra-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-4.18.0-240.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-4.18.0-240.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-4.18.0-240.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-4.18.0-240.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-4.18.0-240.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-devel-4.18.0-240.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-devel-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-4.18.0-240.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-4.18.0-240.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-4.18.0-240.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) release = 'CentOS-' + package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-whitelists / kernel-core / etc');
}
