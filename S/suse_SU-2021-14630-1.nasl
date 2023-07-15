#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:14630-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150536);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/09");

  script_cve_id(
    "CVE-2019-16746",
    "CVE-2020-0404",
    "CVE-2020-0431",
    "CVE-2020-0465",
    "CVE-2020-4788",
    "CVE-2020-11668",
    "CVE-2020-14331",
    "CVE-2020-14353",
    "CVE-2020-14381",
    "CVE-2020-14390",
    "CVE-2020-15436",
    "CVE-2020-15437",
    "CVE-2020-25211",
    "CVE-2020-25284",
    "CVE-2020-25285",
    "CVE-2020-25643",
    "CVE-2020-25656",
    "CVE-2020-25668",
    "CVE-2020-25669",
    "CVE-2020-27068",
    "CVE-2020-27777",
    "CVE-2020-27786",
    "CVE-2020-28915",
    "CVE-2020-28974",
    "CVE-2020-29660",
    "CVE-2020-29661",
    "CVE-2020-36158",
    "CVE-2021-3347"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:14630-1");

  script_name(english:"SUSE SLES11 Security Update : kernel (SUSE-SU-2021:14630-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2021:14630-1 advisory.

  - An issue was discovered in net/wireless/nl80211.c in the Linux kernel through 5.2.17. It does not check
    the length of variable elements in a beacon head, leading to a buffer overflow. (CVE-2019-16746)

  - In uvc_scan_chain_forward of uvc_driver.c, there is a possible linked list corruption due to an unusual
    root cause. This could lead to local escalation of privilege in the kernel with no additional execution
    privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android
    kernelAndroid ID: A-111893654References: Upstream kernel (CVE-2020-0404)

  - In kbd_keycode of keyboard.c, there is a possible out of bounds write due to a missing bounds check. This
    could lead to local escalation of privilege with no additional execution privileges needed. User
    interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-144161459
    (CVE-2020-0431)

  - In various methods of hid-multitouch.c, there is a possible out of bounds write due to a missing bounds
    check. This could lead to local escalation of privilege with no additional execution privileges needed.
    User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-162844689References: Upstream kernel (CVE-2020-0465)

  - In the Linux kernel before 5.6.1, drivers/media/usb/gspca/xirlink_cit.c (aka the Xirlink camera USB
    driver) mishandles invalid descriptors, aka CID-a246b4d54770. (CVE-2020-11668)

  - A flaw was found in the Linux kernels implementation of the invert video code on VGA consoles when a
    local attacker attempts to resize the console, calling an ioctl VT_RESIZE, which causes an out-of-bounds
    write to occur. This flaw allows a local user with access to the VGA console to crash the system,
    potentially escalating their privileges on the system. The highest threat from this vulnerability is to
    data confidentiality and integrity as well as system availability. (CVE-2020-14331)

  - ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2017-18270. Reason: This candidate is a
    duplicate of CVE-2017-18270. Notes: All CVE users should reference CVE-2017-18270 instead of this
    candidate. All references and descriptions in this candidate have been removed to prevent accidental
    usage. (CVE-2020-14353)

  - A flaw was found in the Linux kernels futex implementation. This flaw allows a local attacker to corrupt
    system memory or escalate their privileges when creating a futex on a filesystem that is about to be
    unmounted. The highest threat from this vulnerability is to confidentiality, integrity, as well as system
    availability. (CVE-2020-14381)

  - A flaw was found in the Linux kernel in versions before 5.9-rc6. When changing screen size, an out-of-
    bounds memory write can occur leading to memory corruption or a denial of service. Due to the nature of
    the flaw, privilege escalation cannot be fully ruled out. (CVE-2020-14390)

  - Use-after-free vulnerability in fs/block_dev.c in the Linux kernel before 5.8 allows local users to gain
    privileges or cause a denial of service by leveraging improper access to a certain error field.
    (CVE-2020-15436)

  - The Linux kernel before version 5.8 is vulnerable to a NULL pointer dereference in
    drivers/tty/serial/8250/8250_core.c:serial8250_isa_init_ports() that allows local users to cause a denial
    of service by using the p->serial_in pointer which uninitialized. (CVE-2020-15437)

  - In the Linux kernel through 5.8.7, local attackers able to inject conntrack netlink configuration could
    overflow a local buffer, causing crashes or triggering use of incorrect protocol numbers in
    ctnetlink_parse_tuple_filter in net/netfilter/nf_conntrack_netlink.c, aka CID-1cc5ef91d2ff.
    (CVE-2020-25211)

  - The rbd block device driver in drivers/block/rbd.c in the Linux kernel through 5.8.9 used incomplete
    permission checking for access to rbd devices, which could be leveraged by local attackers to map or unmap
    rbd block devices, aka CID-f44d04e696fe. (CVE-2020-25284)

  - A race condition between hugetlb sysctl handlers in mm/hugetlb.c in the Linux kernel before 5.8.8 could be
    used by local attackers to corrupt memory, cause a NULL pointer dereference, or possibly have unspecified
    other impact, aka CID-17743798d812. (CVE-2020-25285)

  - A flaw was found in the HDLC_PPP module of the Linux kernel in versions before 5.9-rc7. Memory corruption
    and a read overflow is caused by improper input validation in the ppp_cp_parse_cr function which can cause
    the system to crash or cause a denial of service. The highest threat from this vulnerability is to data
    confidentiality and integrity as well as system availability. (CVE-2020-25643)

  - A flaw was found in the Linux kernel. A use-after-free was found in the way the console subsystem was
    using ioctls KDGKBSENT and KDSKBSENT. A local user could use this flaw to get read memory access out of
    bounds. The highest threat from this vulnerability is to data confidentiality. (CVE-2020-25656)

  - A flaw was found in Linux Kernel because access to the global variable fg_console is not properly
    synchronized leading to a use after free in con_font_op. (CVE-2020-25668)

  - A vulnerability was found in the Linux Kernel where the function sunkbd_reinit having been scheduled by
    sunkbd_interrupt before sunkbd being freed. Though the dangling pointer is set to NULL in
    sunkbd_disconnect, there is still an alias in sunkbd_reinit causing Use After Free. (CVE-2020-25669)

  - In the nl80211_policy policy of nl80211.c, there is a possible out of bounds read due to a missing bounds
    check. This could lead to local information disclosure with System execution privileges needed. User
    interaction is not required for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-119770583 (CVE-2020-27068)

  - A flaw was found in the way RTAS handled memory accesses in userspace to kernel communication. On a locked
    down (usually due to Secure Boot) guest system running on top of PowerVM or KVM hypervisors (pseries
    platform) a root like local user could use this flaw to further increase their privileges to that of a
    running kernel. (CVE-2020-27777)

  - A flaw was found in the Linux kernels implementation of MIDI, where an attacker with a local account and
    the permissions to issue ioctl commands to midi devices could trigger a use-after-free issue. A write to
    this specific memory while freed and before use causes the flow of execution to change and possibly allow
    for memory corruption or privilege escalation. The highest threat from this vulnerability is to
    confidentiality, integrity, as well as system availability. (CVE-2020-27786)

  - A buffer over-read (at the framebuffer layer) in the fbcon code in the Linux kernel before 5.8.15 could be
    used by local attackers to read kernel memory, aka CID-6735b4632def. (CVE-2020-28915)

  - A slab-out-of-bounds read in fbcon in the Linux kernel before 5.9.7 could be used by local attackers to
    read privileged information or potentially crash the kernel, aka CID-3c4e0dff2095. This occurs because
    KD_FONT_OP_COPY in drivers/tty/vt/vt.c can be used for manipulations such as font height. (CVE-2020-28974)

  - A locking inconsistency issue was discovered in the tty subsystem of the Linux kernel through 5.9.13.
    drivers/tty/tty_io.c and drivers/tty/tty_jobctrl.c may allow a read-after-free attack against TIOCGSID,
    aka CID-c8bcd9c5be24. (CVE-2020-29660)

  - A locking issue was discovered in the tty subsystem of the Linux kernel through 5.9.13.
    drivers/tty/tty_jobctrl.c allows a use-after-free attack against TIOCSPGRP, aka CID-54ffccbf053b.
    (CVE-2020-29661)

  - mwifiex_cmd_802_11_ad_hoc_start in drivers/net/wireless/marvell/mwifiex/join.c in the Linux kernel through
    5.10.4 might allow remote attackers to execute arbitrary code via a long SSID value, aka CID-5c455c5ab332.
    (CVE-2020-36158)

  - IBM Power9 (AIX 7.1, 7.2, and VIOS 3.1) processors could allow a local user to obtain sensitive
    information from the data in the L1 cache under extenuating circumstances. IBM X-Force ID: 189296.
    (CVE-2020-4788)

  - An issue was discovered in the Linux kernel through 5.10.11. PI futexes have a kernel stack use-after-free
    during fault handling, allowing local users to execute code in the kernel, aka CID-34b1a1ce1458.
    (CVE-2021-3347)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1152107");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1168952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1173659");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1173942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174205");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174247");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174993");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1175691");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176011");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176012");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176235");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176253");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176278");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176423");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176485");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176722");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176896");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177206");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177226");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177766");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177906");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178123");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178182");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178589");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178590");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178622");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178886");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179107");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179140");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179141");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179419");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179616");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179745");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179877");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180029");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180030");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180052");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180086");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181158");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181166");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181349");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181553");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-February/008335.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56f42edd");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-16746");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-0404");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-0431");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-0465");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-11668");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14331");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14353");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14381");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14390");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-15436");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-15437");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25211");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25284");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25285");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25643");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25656");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25668");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25669");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27068");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27777");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27786");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-28915");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-28974");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29660");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29661");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36158");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-4788");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3347");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27068");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/16");
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

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'kernel-default-3.0.101-108.120', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-default-base-3.0.101-108.120', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-default-devel-3.0.101-108.120', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-default-man-3.0.101-108.120', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-ec2-3.0.101-108.120', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-ec2-3.0.101-108.120', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-ec2-base-3.0.101-108.120', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-ec2-base-3.0.101-108.120', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-ec2-devel-3.0.101-108.120', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-ec2-devel-3.0.101-108.120', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-pae-3.0.101-108.120', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-pae-base-3.0.101-108.120', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-pae-devel-3.0.101-108.120', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-source-3.0.101-108.120', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-syms-3.0.101-108.120', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-trace-3.0.101-108.120', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-trace-base-3.0.101-108.120', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-trace-devel-3.0.101-108.120', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-xen-3.0.101-108.120', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-xen-3.0.101-108.120', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-xen-base-3.0.101-108.120', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-xen-base-3.0.101-108.120', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-xen-devel-3.0.101-108.120', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-xen-devel-3.0.101-108.120', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-default-3.0.101-108.120', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-default-base-3.0.101-108.120', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-default-devel-3.0.101-108.120', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-default-man-3.0.101-108.120', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-ec2-3.0.101-108.120', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-ec2-3.0.101-108.120', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-ec2-base-3.0.101-108.120', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-ec2-base-3.0.101-108.120', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-ec2-devel-3.0.101-108.120', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-ec2-devel-3.0.101-108.120', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-pae-3.0.101-108.120', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-pae-base-3.0.101-108.120', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-pae-devel-3.0.101-108.120', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-source-3.0.101-108.120', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-syms-3.0.101-108.120', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-trace-3.0.101-108.120', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-trace-base-3.0.101-108.120', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-trace-devel-3.0.101-108.120', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-xen-3.0.101-108.120', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-xen-3.0.101-108.120', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-xen-base-3.0.101-108.120', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-xen-base-3.0.101-108.120', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-xen-devel-3.0.101-108.120', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-xen-devel-3.0.101-108.120', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'}
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
