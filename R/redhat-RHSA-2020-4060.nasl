##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:4060. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141057);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

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

  script_name(english:"RHEL 7 : kernel (RHSA-2020:4060)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:4060 advisory.

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

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2017-18551");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-20836");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-9454");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-9458");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-12614");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-15217");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-15807");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-15917");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-16231");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-16233");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-16994");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-17053");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-17055");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-18808");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19046");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19055");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19058");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19059");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19062");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19063");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19332");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19447");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19523");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19524");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19530");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19534");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19537");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19767");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19807");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-20054");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-20095");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-20636");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-1749");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2732");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-8647");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-8649");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-9383");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10690");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10732");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10742");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10751");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10942");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11565");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-12770");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-12826");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14305");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:4060");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1707796");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1718176");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1745528");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1747216");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1757368");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1758242");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1758248");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1759681");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1760100");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1760310");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1760420");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1774988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1775015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1775021");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1775042");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1775047");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1775074");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1777418");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1779594");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1781679");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1783434");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1783459");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1783518");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1783540");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1783561");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1786078");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1786160");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1790063");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1791954");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1802555");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1802563");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1805135");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1809833");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1810685");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1817141");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1817718");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1818818");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1819377");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1822077");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1824059");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1824918");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1831399");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1834845");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1835127");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1839634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1850716");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-20836");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 94, 119, 121, 125, 200, 250, 319, 349, 362, 400, 401, 416, 476, 772, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-bootwrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2017-18551', 'CVE-2018-20836', 'CVE-2019-9454', 'CVE-2019-9458', 'CVE-2019-12614', 'CVE-2019-15217', 'CVE-2019-15807', 'CVE-2019-15917', 'CVE-2019-16231', 'CVE-2019-16233', 'CVE-2019-16994', 'CVE-2019-17053', 'CVE-2019-17055', 'CVE-2019-18808', 'CVE-2019-19046', 'CVE-2019-19055', 'CVE-2019-19058', 'CVE-2019-19059', 'CVE-2019-19062', 'CVE-2019-19063', 'CVE-2019-19332', 'CVE-2019-19447', 'CVE-2019-19523', 'CVE-2019-19524', 'CVE-2019-19530', 'CVE-2019-19534', 'CVE-2019-19537', 'CVE-2019-19767', 'CVE-2019-19807', 'CVE-2019-20054', 'CVE-2019-20095', 'CVE-2019-20636', 'CVE-2020-1749', 'CVE-2020-2732', 'CVE-2020-8647', 'CVE-2020-8649', 'CVE-2020-9383', 'CVE-2020-10690', 'CVE-2020-10732', 'CVE-2020-10742', 'CVE-2020-10751', 'CVE-2020-10942', 'CVE-2020-11565', 'CVE-2020-12770', 'CVE-2020-12826', 'CVE-2020-14305');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2020:4060');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/optional/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/optional/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/optional/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/supplementary/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/supplementary/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/debug',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/optional/debug',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/optional/os',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/optional/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/os',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/source/SRPMS',
      'content/dist/rhel/client/7/7Client/x86_64/debug',
      'content/dist/rhel/client/7/7Client/x86_64/optional/debug',
      'content/dist/rhel/client/7/7Client/x86_64/optional/os',
      'content/dist/rhel/client/7/7Client/x86_64/optional/source/SRPMS',
      'content/dist/rhel/client/7/7Client/x86_64/oracle-java-rm/os',
      'content/dist/rhel/client/7/7Client/x86_64/os',
      'content/dist/rhel/client/7/7Client/x86_64/source/SRPMS',
      'content/dist/rhel/client/7/7Client/x86_64/supplementary/debug',
      'content/dist/rhel/client/7/7Client/x86_64/supplementary/os',
      'content/dist/rhel/client/7/7Client/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/debug',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/optional/debug',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/optional/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/optional/source/SRPMS',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/oracle-java-rm/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/source/SRPMS',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/supplementary/debug',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/supplementary/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/highavailability/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/highavailability/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/optional/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/optional/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/optional/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/resilientstorage/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/resilientstorage/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap-hana/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap-hana/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap-hana/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/supplementary/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/supplementary/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/supplementary/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/debug',
      'content/dist/rhel/power/7/7Server/ppc64/optional/debug',
      'content/dist/rhel/power/7/7Server/ppc64/optional/os',
      'content/dist/rhel/power/7/7Server/ppc64/optional/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/os',
      'content/dist/rhel/power/7/7Server/ppc64/sap/debug',
      'content/dist/rhel/power/7/7Server/ppc64/sap/os',
      'content/dist/rhel/power/7/7Server/ppc64/sap/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/supplementary/debug',
      'content/dist/rhel/power/7/7Server/ppc64/supplementary/os',
      'content/dist/rhel/power/7/7Server/ppc64/supplementary/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/debug',
      'content/dist/rhel/server/7/7Server/x86_64/highavailability/debug',
      'content/dist/rhel/server/7/7Server/x86_64/highavailability/os',
      'content/dist/rhel/server/7/7Server/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/nfv/debug',
      'content/dist/rhel/server/7/7Server/x86_64/nfv/os',
      'content/dist/rhel/server/7/7Server/x86_64/nfv/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/optional/debug',
      'content/dist/rhel/server/7/7Server/x86_64/optional/os',
      'content/dist/rhel/server/7/7Server/x86_64/optional/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/oracle-java-rm/os',
      'content/dist/rhel/server/7/7Server/x86_64/os',
      'content/dist/rhel/server/7/7Server/x86_64/resilientstorage/debug',
      'content/dist/rhel/server/7/7Server/x86_64/resilientstorage/os',
      'content/dist/rhel/server/7/7Server/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rt/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rt/os',
      'content/dist/rhel/server/7/7Server/x86_64/rt/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/sap-hana/debug',
      'content/dist/rhel/server/7/7Server/x86_64/sap-hana/os',
      'content/dist/rhel/server/7/7Server/x86_64/sap-hana/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/sap/debug',
      'content/dist/rhel/server/7/7Server/x86_64/sap/os',
      'content/dist/rhel/server/7/7Server/x86_64/sap/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/supplementary/debug',
      'content/dist/rhel/server/7/7Server/x86_64/supplementary/os',
      'content/dist/rhel/server/7/7Server/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/highavailability/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/highavailability/os',
      'content/dist/rhel/system-z/7/7Server/s390x/highavailability/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/optional/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/optional/os',
      'content/dist/rhel/system-z/7/7Server/s390x/optional/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/os',
      'content/dist/rhel/system-z/7/7Server/s390x/resilientstorage/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/resilientstorage/os',
      'content/dist/rhel/system-z/7/7Server/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/sap/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/sap/os',
      'content/dist/rhel/system-z/7/7Server/s390x/sap/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/supplementary/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/supplementary/os',
      'content/dist/rhel/system-z/7/7Server/s390x/supplementary/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/optional/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/optional/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/optional/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/oracle-java-rm/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/supplementary/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/supplementary/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/supplementary/source/SRPMS',
      'content/fastrack/rhel/client/7/x86_64/debug',
      'content/fastrack/rhel/client/7/x86_64/optional/debug',
      'content/fastrack/rhel/client/7/x86_64/optional/os',
      'content/fastrack/rhel/client/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/client/7/x86_64/os',
      'content/fastrack/rhel/client/7/x86_64/source/SRPMS',
      'content/fastrack/rhel/computenode/7/x86_64/debug',
      'content/fastrack/rhel/computenode/7/x86_64/optional/debug',
      'content/fastrack/rhel/computenode/7/x86_64/optional/os',
      'content/fastrack/rhel/computenode/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/computenode/7/x86_64/os',
      'content/fastrack/rhel/computenode/7/x86_64/source/SRPMS',
      'content/fastrack/rhel/power/7/ppc64/debug',
      'content/fastrack/rhel/power/7/ppc64/optional/debug',
      'content/fastrack/rhel/power/7/ppc64/optional/os',
      'content/fastrack/rhel/power/7/ppc64/optional/source/SRPMS',
      'content/fastrack/rhel/power/7/ppc64/os',
      'content/fastrack/rhel/power/7/ppc64/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/debug',
      'content/fastrack/rhel/server/7/x86_64/highavailability/debug',
      'content/fastrack/rhel/server/7/x86_64/highavailability/os',
      'content/fastrack/rhel/server/7/x86_64/highavailability/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/optional/debug',
      'content/fastrack/rhel/server/7/x86_64/optional/os',
      'content/fastrack/rhel/server/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/os',
      'content/fastrack/rhel/server/7/x86_64/resilientstorage/debug',
      'content/fastrack/rhel/server/7/x86_64/resilientstorage/os',
      'content/fastrack/rhel/server/7/x86_64/resilientstorage/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/source/SRPMS',
      'content/fastrack/rhel/system-z/7/s390x/debug',
      'content/fastrack/rhel/system-z/7/s390x/optional/debug',
      'content/fastrack/rhel/system-z/7/s390x/optional/os',
      'content/fastrack/rhel/system-z/7/s390x/optional/source/SRPMS',
      'content/fastrack/rhel/system-z/7/s390x/os',
      'content/fastrack/rhel/system-z/7/s390x/source/SRPMS',
      'content/fastrack/rhel/workstation/7/x86_64/debug',
      'content/fastrack/rhel/workstation/7/x86_64/optional/debug',
      'content/fastrack/rhel/workstation/7/x86_64/optional/os',
      'content/fastrack/rhel/workstation/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/workstation/7/x86_64/os',
      'content/fastrack/rhel/workstation/7/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'bpftool-3.10.0-1160.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'bpftool-3.10.0-1160.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'bpftool-3.10.0-1160.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'bpftool-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-3.10.0-1160.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-3.10.0-1160.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-3.10.0-1160.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-abi-whitelists-3.10.0-1160.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-bootwrapper-3.10.0-1160.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-bootwrapper-3.10.0-1160.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-3.10.0-1160.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-3.10.0-1160.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-3.10.0-1160.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-3.10.0-1160.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-3.10.0-1160.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-3.10.0-1160.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-3.10.0-1160.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-3.10.0-1160.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-3.10.0-1160.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-3.10.0-1160.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-3.10.0-1160.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-3.10.0-1160.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-3.10.0-1160.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-devel-3.10.0-1160.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-3.10.0-1160.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-3.10.0-1160.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-3.10.0-1160.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-3.10.0-1160.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-3.10.0-1160.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-3.10.0-1160.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-3.10.0-1160.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-3.10.0-1160.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-3.10.0-1160.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-3.10.0-1160.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-3.10.0-1160.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-3.10.0-1160.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-3.10.0-1160.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
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
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-whitelists / kernel-bootwrapper / etc');
}
