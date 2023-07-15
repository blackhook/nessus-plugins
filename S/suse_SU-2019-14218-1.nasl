#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2019:14218-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150533);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/10");

  script_cve_id(
    "CVE-2017-18509",
    "CVE-2017-18551",
    "CVE-2018-12207",
    "CVE-2018-20976",
    "CVE-2019-9456",
    "CVE-2019-10220",
    "CVE-2019-11135",
    "CVE-2019-14821",
    "CVE-2019-14835",
    "CVE-2019-15118",
    "CVE-2019-15212",
    "CVE-2019-15216",
    "CVE-2019-15217",
    "CVE-2019-15219",
    "CVE-2019-15291",
    "CVE-2019-15292",
    "CVE-2019-15505",
    "CVE-2019-15807",
    "CVE-2019-15902",
    "CVE-2019-15927",
    "CVE-2019-16232",
    "CVE-2019-16233",
    "CVE-2019-16234",
    "CVE-2019-16413",
    "CVE-2019-17052",
    "CVE-2019-17053",
    "CVE-2019-17054",
    "CVE-2019-17055",
    "CVE-2019-17133"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2019:14218-1");

  script_name(english:"SUSE SLES11 Security Update : kernel (SUSE-SU-2019:14218-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2019:14218-1 advisory.

  - An issue was discovered in net/ipv6/ip6mr.c in the Linux kernel before 4.11. By setting a specific socket
    option, an attacker can control a pointer in kernel land and cause an inet_csk_listen_stop general
    protection fault, or potentially execute arbitrary code under certain circumstances. The issue can be
    triggered as root (e.g., inside a default LXC container or with the CAP_NET_ADMIN capability) or after
    namespace unsharing. This occurs because sk_type and protocol are not checked in the appropriate part of
    the ip6_mroute_* functions. NOTE: this affects Linux distributions that use 4.9.x longterm kernels before
    4.9.187. (CVE-2017-18509)

  - An issue was discovered in drivers/i2c/i2c-core-smbus.c in the Linux kernel before 4.14.15. There is an
    out of bounds write in the function i2c_smbus_xfer_emulated. (CVE-2017-18551)

  - Improper invalidation for page table updates by a virtual guest operating system for multiple Intel(R)
    Processors may allow an authenticated user to potentially enable denial of service of the host system via
    local access. (CVE-2018-12207)

  - An issue was discovered in fs/xfs/xfs_super.c in the Linux kernel before 4.18. A use after free exists,
    related to xfs_fs_fill_super failure. (CVE-2018-20976)

  - Linux kernel CIFS implementation, version 4.9.0 is vulnerable to a relative paths injection in directory
    entry lists. (CVE-2019-10220)

  - TSX Asynchronous Abort condition on some CPUs utilizing speculative execution may allow an authenticated
    user to potentially enable information disclosure via a side channel with local access. (CVE-2019-11135)

  - An out-of-bounds access issue was found in the Linux kernel, all versions through 5.3, in the way Linux
    kernel's KVM hypervisor implements the Coalesced MMIO write operation. It operates on an MMIO ring buffer
    'struct kvm_coalesced_mmio' object, wherein write indices 'ring->first' and 'ring->last' value could be
    supplied by a host user-space process. An unprivileged host user or process with access to '/dev/kvm'
    device could use this flaw to crash the host kernel, resulting in a denial of service or potentially
    escalating privileges on the system. (CVE-2019-14821)

  - A buffer overflow flaw was found, in versions from 2.6.34 to 5.2.x, in the way Linux kernel's vhost
    functionality that translates virtqueue buffers to IOVs, logged the buffer descriptors during migration. A
    privileged guest user able to pass descriptors with invalid length to the host when migration is underway,
    could use this flaw to increase their privileges on the host. (CVE-2019-14835)

  - check_input_term in sound/usb/mixer.c in the Linux kernel through 5.2.9 mishandles recursion, leading to
    kernel stack exhaustion. (CVE-2019-15118)

  - An issue was discovered in the Linux kernel before 5.1.8. There is a double-free caused by a malicious USB
    device in the drivers/usb/misc/rio500.c driver. (CVE-2019-15212)

  - An issue was discovered in the Linux kernel before 5.0.14. There is a NULL pointer dereference caused by a
    malicious USB device in the drivers/usb/misc/yurex.c driver. (CVE-2019-15216)

  - An issue was discovered in the Linux kernel before 5.2.3. There is a NULL pointer dereference caused by a
    malicious USB device in the drivers/media/usb/zr364xx/zr364xx.c driver. (CVE-2019-15217)

  - An issue was discovered in the Linux kernel before 5.1.8. There is a NULL pointer dereference caused by a
    malicious USB device in the drivers/usb/misc/sisusbvga/sisusb.c driver. (CVE-2019-15219)

  - An issue was discovered in the Linux kernel through 5.2.9. There is a NULL pointer dereference caused by a
    malicious USB device in the flexcop_usb_probe function in the drivers/media/usb/b2c2/flexcop-usb.c driver.
    (CVE-2019-15291)

  - An issue was discovered in the Linux kernel before 5.0.9. There is a use-after-free in atalk_proc_exit,
    related to net/appletalk/atalk_proc.c, net/appletalk/ddp.c, and net/appletalk/sysctl_net_atalk.c.
    (CVE-2019-15292)

  - drivers/media/usb/dvb-usb/technisat-usb2.c in the Linux kernel through 5.2.9 has an out-of-bounds read via
    crafted USB device traffic (which may be remote via usbip or usbredir). (CVE-2019-15505)

  - In the Linux kernel before 5.1.13, there is a memory leak in drivers/scsi/libsas/sas_expander.c when SAS
    expander discovery fails. This will cause a BUG and denial of service. (CVE-2019-15807)

  - A backporting error was discovered in the Linux stable/longterm kernel 4.4.x through 4.4.190, 4.9.x
    through 4.9.190, 4.14.x through 4.14.141, 4.19.x through 4.19.69, and 5.2.x through 5.2.11. Misuse of the
    upstream x86/ptrace: Fix possible spectre-v1 in ptrace_get_debugreg() commit reintroduced the Spectre
    vulnerability that it aimed to eliminate. This occurred because the backport process depends on cherry
    picking specific commits, and because two (correctly ordered) code lines were swapped. (CVE-2019-15902)

  - An issue was discovered in the Linux kernel before 4.20.2. An out-of-bounds access exists in the function
    build_audio_procunit in the file sound/usb/mixer.c. (CVE-2019-15927)

  - drivers/net/wireless/marvell/libertas/if_sdio.c in the Linux kernel 5.2.14 does not check the
    alloc_workqueue return value, leading to a NULL pointer dereference. (CVE-2019-16232)

  - drivers/scsi/qla2xxx/qla_os.c in the Linux kernel 5.2.14 does not check the alloc_workqueue return value,
    leading to a NULL pointer dereference. (CVE-2019-16233)

  - drivers/net/wireless/intel/iwlwifi/pcie/trans.c in the Linux kernel 5.2.14 does not check the
    alloc_workqueue return value, leading to a NULL pointer dereference. (CVE-2019-16234)

  - An issue was discovered in the Linux kernel before 5.0.4. The 9p filesystem did not protect i_size_write()
    properly, which causes an i_size_read() infinite loop and denial of service on SMP systems.
    (CVE-2019-16413)

  - ax25_create in net/ax25/af_ax25.c in the AF_AX25 network module in the Linux kernel 3.16 through 5.3.2
    does not enforce CAP_NET_RAW, which means that unprivileged users can create a raw socket, aka
    CID-0614e2b73768. (CVE-2019-17052)

  - ieee802154_create in net/ieee802154/socket.c in the AF_IEEE802154 network module in the Linux kernel
    through 5.3.2 does not enforce CAP_NET_RAW, which means that unprivileged users can create a raw socket,
    aka CID-e69dbd4619e7. (CVE-2019-17053)

  - atalk_create in net/appletalk/ddp.c in the AF_APPLETALK network module in the Linux kernel through 5.3.2
    does not enforce CAP_NET_RAW, which means that unprivileged users can create a raw socket, aka
    CID-6cc03e8aa36c. (CVE-2019-17054)

  - base_sock_create in drivers/isdn/mISDN/socket.c in the AF_ISDN network module in the Linux kernel through
    5.3.2 does not enforce CAP_NET_RAW, which means that unprivileged users can create a raw socket, aka
    CID-b91ee4aa2a21. (CVE-2019-17055)

  - In the Linux kernel through 5.3.2, cfg80211_mgd_wext_giwessid in net/wireless/wext-sme.c does not reject a
    long SSID IE, leading to a Buffer Overflow. (CVE-2019-17133)

  - In the Android kernel in Pixel C USB monitor driver there is a possible OOB write due to a missing bounds
    check. This could lead to local escalation of privilege with System execution privileges needed. User
    interaction is not needed for exploitation. (CVE-2019-9456)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/802154");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/936875");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1101061");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1113201");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1117665");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1131107");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1143327");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1144903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1145477");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1145922");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1146163");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1146285");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1146361");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1146391");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1146524");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1146540");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1146547");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1146678");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1147122");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1148938");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1149376");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1149522");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1150025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1150112");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1150452");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1150457");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1150465");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1150599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1151347");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1151350");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1152779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1152782");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1152786");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1152789");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1153158");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1155671");
  # https://lists.suse.com/pipermail/sle-security-updates/2019-November/006135.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a4cd4f8");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-18509");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-18551");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-12207");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-20976");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-10220");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11135");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-14821");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-14835");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15118");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15212");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15216");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15217");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15219");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15291");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15292");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15505");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15807");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15902");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15927");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-16232");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-16233");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-16234");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-16413");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-17052");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-17053");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-17054");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-17055");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-17133");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9456");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15505");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigmem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigmem-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigmem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ppc64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ppc64-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ppc64-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES11', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);

pkgs = [
    {'reference':'kernel-default-3.0.101-108.108', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-default-base-3.0.101-108.108', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-default-devel-3.0.101-108.108', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-default-man-3.0.101-108.108', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-ec2-3.0.101-108.108', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-ec2-3.0.101-108.108', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-ec2-base-3.0.101-108.108', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-ec2-base-3.0.101-108.108', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-ec2-devel-3.0.101-108.108', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-ec2-devel-3.0.101-108.108', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-pae-3.0.101-108.108', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-pae-base-3.0.101-108.108', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-pae-devel-3.0.101-108.108', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-source-3.0.101-108.108', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-syms-3.0.101-108.108', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-trace-3.0.101-108.108', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-trace-base-3.0.101-108.108', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-trace-devel-3.0.101-108.108', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-xen-3.0.101-108.108', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-xen-3.0.101-108.108', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-xen-base-3.0.101-108.108', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-xen-base-3.0.101-108.108', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-xen-devel-3.0.101-108.108', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-xen-devel-3.0.101-108.108', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-default-3.0.101-108.108', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-default-base-3.0.101-108.108', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-default-devel-3.0.101-108.108', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-default-man-3.0.101-108.108', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-ec2-3.0.101-108.108', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-ec2-3.0.101-108.108', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-ec2-base-3.0.101-108.108', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-ec2-base-3.0.101-108.108', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-ec2-devel-3.0.101-108.108', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-ec2-devel-3.0.101-108.108', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-pae-3.0.101-108.108', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-pae-base-3.0.101-108.108', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-pae-devel-3.0.101-108.108', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-source-3.0.101-108.108', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-syms-3.0.101-108.108', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-trace-3.0.101-108.108', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-trace-base-3.0.101-108.108', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-trace-devel-3.0.101-108.108', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-xen-3.0.101-108.108', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-xen-3.0.101-108.108', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-xen-base-3.0.101-108.108', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-xen-base-3.0.101-108.108', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-xen-devel-3.0.101-108.108', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-xen-devel-3.0.101-108.108', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  exists_check = NULL;
  rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release && exists_check) {
    if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
  else if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-default / kernel-default-base / kernel-default-devel / etc');
}
