##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:4609. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142382);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id(
    "CVE-2019-9455",
    "CVE-2019-9458",
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
    "CVE-2020-10774",
    "CVE-2020-10942",
    "CVE-2020-11565",
    "CVE-2020-11668",
    "CVE-2020-12655",
    "CVE-2020-12659",
    "CVE-2020-12770",
    "CVE-2020-12826",
    "CVE-2020-14381",
    "CVE-2020-25641"
  );
  script_xref(name:"RHSA", value:"2020:4609");

  script_name(english:"RHEL 8 : kernel-rt (RHSA-2020:4609)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:4609 advisory.

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

  - kernel: possibility of memory disclosure when reading the file /proc/sys/kernel/rh_features
    (CVE-2020-10774)

  - kernel: vhost-net: stack overflow in get_raw_socket while checking sk_family field (CVE-2020-10942)

  - kernel: out-of-bounds write in mpol_parse_str function in mm/mempolicy.c (CVE-2020-11565)

  - kernel: mishandles invalid descriptors in drivers/media/usb/gspca/xirlink_cit.c (CVE-2020-11668)

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

  - kernel: use-after-free in route4_change() in net/sched/cls_route.c (CVE-2021-3715)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-9455");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-9458");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-15917");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-15925");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-16231");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-16233");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-18808");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-18809");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19046");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19056");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19062");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19063");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19068");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19072");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19319");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19332");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19447");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19524");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19533");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19537");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19543");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19767");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19770");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-20054");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-20636");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-0305");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-8647");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-8648");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-8649");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10732");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10751");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10774");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10942");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11565");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11668");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-12655");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-12659");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-12770");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-12826");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14381");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25641");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3715");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:4609");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1759052");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1760100");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1760310");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1760420");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1774946");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1774963");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1774988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1775015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1775021");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1775097");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1777418");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1777449");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1779594");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1781679");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1781810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1783459");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1783534");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1783561");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1784130");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1786160");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1786179");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1790063");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1802555");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1802559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1802563");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1817718");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1819377");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1819399");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1822077");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1824059");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1824792");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1824918");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1831399");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1832543");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1832876");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1834845");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1839634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1846964");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1860065");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1874311");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1881424");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1993988");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12659");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-19770");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 94, 119, 200, 349, 362, 400, 401, 416, 476, 772, 787, 805, 835, 908, 909);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-modules-extra");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2019-9455', 'CVE-2019-9458', 'CVE-2019-15917', 'CVE-2019-15925', 'CVE-2019-16231', 'CVE-2019-16233', 'CVE-2019-18808', 'CVE-2019-18809', 'CVE-2019-19046', 'CVE-2019-19056', 'CVE-2019-19062', 'CVE-2019-19063', 'CVE-2019-19068', 'CVE-2019-19072', 'CVE-2019-19319', 'CVE-2019-19332', 'CVE-2019-19447', 'CVE-2019-19524', 'CVE-2019-19533', 'CVE-2019-19537', 'CVE-2019-19543', 'CVE-2019-19767', 'CVE-2019-19770', 'CVE-2019-20054', 'CVE-2019-20636', 'CVE-2020-0305', 'CVE-2020-8647', 'CVE-2020-8648', 'CVE-2020-8649', 'CVE-2020-10732', 'CVE-2020-10751', 'CVE-2020-10774', 'CVE-2020-10942', 'CVE-2020-11565', 'CVE-2020-11668', 'CVE-2020-12655', 'CVE-2020-12659', 'CVE-2020-12770', 'CVE-2020-12826', 'CVE-2020-14381', 'CVE-2020-25641', 'CVE-2021-3715');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2020:4609');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel8/8.4/x86_64/appstream/debug',
      'content/aus/rhel8/8.4/x86_64/appstream/os',
      'content/aus/rhel8/8.4/x86_64/appstream/source/SRPMS',
      'content/aus/rhel8/8.4/x86_64/baseos/debug',
      'content/aus/rhel8/8.4/x86_64/baseos/os',
      'content/aus/rhel8/8.4/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/appstream/debug',
      'content/e4s/rhel8/8.4/x86_64/appstream/os',
      'content/e4s/rhel8/8.4/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/baseos/debug',
      'content/e4s/rhel8/8.4/x86_64/baseos/os',
      'content/e4s/rhel8/8.4/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/highavailability/debug',
      'content/e4s/rhel8/8.4/x86_64/highavailability/os',
      'content/e4s/rhel8/8.4/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/sap-solutions/debug',
      'content/e4s/rhel8/8.4/x86_64/sap-solutions/os',
      'content/e4s/rhel8/8.4/x86_64/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/sap/debug',
      'content/e4s/rhel8/8.4/x86_64/sap/os',
      'content/e4s/rhel8/8.4/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/appstream/debug',
      'content/eus/rhel8/8.4/x86_64/appstream/os',
      'content/eus/rhel8/8.4/x86_64/appstream/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/baseos/debug',
      'content/eus/rhel8/8.4/x86_64/baseos/os',
      'content/eus/rhel8/8.4/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/codeready-builder/debug',
      'content/eus/rhel8/8.4/x86_64/codeready-builder/os',
      'content/eus/rhel8/8.4/x86_64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/highavailability/debug',
      'content/eus/rhel8/8.4/x86_64/highavailability/os',
      'content/eus/rhel8/8.4/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/resilientstorage/debug',
      'content/eus/rhel8/8.4/x86_64/resilientstorage/os',
      'content/eus/rhel8/8.4/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/sap-solutions/debug',
      'content/eus/rhel8/8.4/x86_64/sap-solutions/os',
      'content/eus/rhel8/8.4/x86_64/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/sap/debug',
      'content/eus/rhel8/8.4/x86_64/sap/os',
      'content/eus/rhel8/8.4/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/supplementary/debug',
      'content/eus/rhel8/8.4/x86_64/supplementary/os',
      'content/eus/rhel8/8.4/x86_64/supplementary/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/appstream/debug',
      'content/tus/rhel8/8.4/x86_64/appstream/os',
      'content/tus/rhel8/8.4/x86_64/appstream/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/baseos/debug',
      'content/tus/rhel8/8.4/x86_64/baseos/os',
      'content/tus/rhel8/8.4/x86_64/baseos/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/highavailability/debug',
      'content/tus/rhel8/8.4/x86_64/highavailability/os',
      'content/tus/rhel8/8.4/x86_64/highavailability/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/nfv/debug',
      'content/tus/rhel8/8.4/x86_64/nfv/os',
      'content/tus/rhel8/8.4/x86_64/nfv/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/rt/debug',
      'content/tus/rhel8/8.4/x86_64/rt/os',
      'content/tus/rhel8/8.4/x86_64/rt/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kernel-rt-4.18.0-240.rt7.54.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-core-4.18.0-240.rt7.54.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-4.18.0-240.rt7.54.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-core-4.18.0-240.rt7.54.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-devel-4.18.0-240.rt7.54.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-kvm-4.18.0-240.rt7.54.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-modules-4.18.0-240.rt7.54.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-modules-extra-4.18.0-240.rt7.54.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-devel-4.18.0-240.rt7.54.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-kvm-4.18.0-240.rt7.54.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-modules-4.18.0-240.rt7.54.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-modules-extra-4.18.0-240.rt7.54.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/aus/rhel8/8.6/x86_64/appstream/debug',
      'content/aus/rhel8/8.6/x86_64/appstream/os',
      'content/aus/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/aus/rhel8/8.6/x86_64/baseos/debug',
      'content/aus/rhel8/8.6/x86_64/baseos/os',
      'content/aus/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/appstream/debug',
      'content/e4s/rhel8/8.6/x86_64/appstream/os',
      'content/e4s/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/baseos/debug',
      'content/e4s/rhel8/8.6/x86_64/baseos/os',
      'content/e4s/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/highavailability/debug',
      'content/e4s/rhel8/8.6/x86_64/highavailability/os',
      'content/e4s/rhel8/8.6/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/sap-solutions/debug',
      'content/e4s/rhel8/8.6/x86_64/sap-solutions/os',
      'content/e4s/rhel8/8.6/x86_64/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/sap/debug',
      'content/e4s/rhel8/8.6/x86_64/sap/os',
      'content/e4s/rhel8/8.6/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/appstream/debug',
      'content/eus/rhel8/8.6/x86_64/appstream/os',
      'content/eus/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/baseos/debug',
      'content/eus/rhel8/8.6/x86_64/baseos/os',
      'content/eus/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/codeready-builder/debug',
      'content/eus/rhel8/8.6/x86_64/codeready-builder/os',
      'content/eus/rhel8/8.6/x86_64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/highavailability/debug',
      'content/eus/rhel8/8.6/x86_64/highavailability/os',
      'content/eus/rhel8/8.6/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/resilientstorage/debug',
      'content/eus/rhel8/8.6/x86_64/resilientstorage/os',
      'content/eus/rhel8/8.6/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/sap-solutions/debug',
      'content/eus/rhel8/8.6/x86_64/sap-solutions/os',
      'content/eus/rhel8/8.6/x86_64/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/sap/debug',
      'content/eus/rhel8/8.6/x86_64/sap/os',
      'content/eus/rhel8/8.6/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/supplementary/debug',
      'content/eus/rhel8/8.6/x86_64/supplementary/os',
      'content/eus/rhel8/8.6/x86_64/supplementary/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/appstream/debug',
      'content/tus/rhel8/8.6/x86_64/appstream/os',
      'content/tus/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/baseos/debug',
      'content/tus/rhel8/8.6/x86_64/baseos/os',
      'content/tus/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/highavailability/debug',
      'content/tus/rhel8/8.6/x86_64/highavailability/os',
      'content/tus/rhel8/8.6/x86_64/highavailability/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/rt/os',
      'content/tus/rhel8/8.6/x86_64/rt/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kernel-rt-4.18.0-240.rt7.54.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-core-4.18.0-240.rt7.54.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-4.18.0-240.rt7.54.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-core-4.18.0-240.rt7.54.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-devel-4.18.0-240.rt7.54.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-kvm-4.18.0-240.rt7.54.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-modules-4.18.0-240.rt7.54.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-modules-extra-4.18.0-240.rt7.54.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-devel-4.18.0-240.rt7.54.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-kvm-4.18.0-240.rt7.54.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-modules-4.18.0-240.rt7.54.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-modules-extra-4.18.0-240.rt7.54.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel8/8/x86_64/appstream/debug',
      'content/dist/rhel8/8/x86_64/appstream/os',
      'content/dist/rhel8/8/x86_64/appstream/source/SRPMS',
      'content/dist/rhel8/8/x86_64/baseos/debug',
      'content/dist/rhel8/8/x86_64/baseos/os',
      'content/dist/rhel8/8/x86_64/baseos/source/SRPMS',
      'content/dist/rhel8/8/x86_64/codeready-builder/debug',
      'content/dist/rhel8/8/x86_64/codeready-builder/os',
      'content/dist/rhel8/8/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/x86_64/highavailability/debug',
      'content/dist/rhel8/8/x86_64/highavailability/os',
      'content/dist/rhel8/8/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel8/8/x86_64/nfv/debug',
      'content/dist/rhel8/8/x86_64/nfv/os',
      'content/dist/rhel8/8/x86_64/nfv/source/SRPMS',
      'content/dist/rhel8/8/x86_64/resilientstorage/debug',
      'content/dist/rhel8/8/x86_64/resilientstorage/os',
      'content/dist/rhel8/8/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel8/8/x86_64/rt/debug',
      'content/dist/rhel8/8/x86_64/rt/os',
      'content/dist/rhel8/8/x86_64/rt/source/SRPMS',
      'content/dist/rhel8/8/x86_64/sap-solutions/debug',
      'content/dist/rhel8/8/x86_64/sap-solutions/os',
      'content/dist/rhel8/8/x86_64/sap-solutions/source/SRPMS',
      'content/dist/rhel8/8/x86_64/sap/debug',
      'content/dist/rhel8/8/x86_64/sap/os',
      'content/dist/rhel8/8/x86_64/sap/source/SRPMS',
      'content/dist/rhel8/8/x86_64/supplementary/debug',
      'content/dist/rhel8/8/x86_64/supplementary/os',
      'content/dist/rhel8/8/x86_64/supplementary/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kernel-rt-4.18.0-240.rt7.54.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-core-4.18.0-240.rt7.54.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-4.18.0-240.rt7.54.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-core-4.18.0-240.rt7.54.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-devel-4.18.0-240.rt7.54.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-kvm-4.18.0-240.rt7.54.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-modules-4.18.0-240.rt7.54.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-modules-extra-4.18.0-240.rt7.54.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-devel-4.18.0-240.rt7.54.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-kvm-4.18.0-240.rt7.54.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-modules-4.18.0-240.rt7.54.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-modules-extra-4.18.0-240.rt7.54.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  var enterprise_linux_flag = rhel_repo_urls_has_content_dist_rhel(repo_urls:repo_relative_urls);
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp']) && !enterprise_linux_flag) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get() + redhat_report_package_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-rt / kernel-rt-core / kernel-rt-debug / kernel-rt-debug-core / etc');
}
