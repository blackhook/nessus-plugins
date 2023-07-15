#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135741);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id(
    "CVE-2019-19036",
    "CVE-2019-19037",
    "CVE-2019-19039",
    "CVE-2019-19815",
    "CVE-2019-20636",
    "CVE-2020-0067",
    "CVE-2020-1749",
    "CVE-2020-11494",
    "CVE-2020-11565",
    "CVE-2020-11608",
    "CVE-2020-11609",
    "CVE-2020-11668",
    "CVE-2020-11669"
  );

  script_name(english:"EulerOS 2.0 SP8 : kernel (EulerOS-SA-2020-1508)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - In f2fs_xattr_generic_list of xattr.c, there is a
    possible out of bounds read due to a missing bounds
    check. This could lead to local information disclosure
    with System execution privileges needed. User
    interaction is not required for
    exploitation.(CVE-2020-0067)

  - An issue was discovered in the Linux kernel before 5.2
    on the powerpc platform.
    arch/powerpc/kernel/idle_book3s.S does not have
    save/restore functionality for PNV_POWERSAVE_AMR,
    PNV_POWERSAVE_UAMOR, and PNV_POWERSAVE_AMOR, aka
    CID-53a712bae5dd.(CVE-2020-11669)

  - In the Linux kernel before 5.6.1,
    drivers/media/usb/gspca/xirlink_cit.c (aka the Xirlink
    camera USB driver) mishandles invalid descriptors, aka
    CID-a246b4d54770.(CVE-2020-11668)

  - In the Linux kernel before 5.4.12,
    drivers/input/input.c has out-of-bounds writes via a
    crafted keycode table, as demonstrated by
    input_set_keycode, aka
    CID-cb222aed03d7.(CVE-2019-20636)

  - An issue was discovered in the Linux kernel before
    5.6.1. drivers/media/usb/gspca/ov519.c allows NULL
    pointer dereferences in ov511_mode_init_regs and
    ov518_mode_init_regs when there are zero endpoints, aka
    CID-998912346c0d.(CVE-2020-11608)

  - An issue was discovered in the stv06xx subsystem in the
    Linux kernel before 5.6.1.
    drivers/media/usb/gspca/stv06xx/stv06xx.c and
    drivers/media/usb/gspca/stv06xx/stv06xx_pb0100.c
    mishandle invalid descriptors, as demonstrated by a
    NULL pointer dereference, aka
    CID-485b06aadb93.(CVE-2020-11609)

  - A flaw was found in the Linux kernel's implementation
    of some networking protocols in IPsec, such as VXLAN
    and GENEVE tunnels over IPv6. When an encrypted tunnel
    is created between two hosts, the kernel isn't
    correctly routing tunneled data over the encrypted link
    rather sending the data unencrypted. This would allow
    anyone in between the two endpoints to read the traffic
    unencrypted. The main threat from this vulnerability is
    to data confidentiality.(CVE-2020-1749)

  - An issue was discovered in the Linux kernel through
    5.6.2. mpol_parse_str in mm/mempolicy.c has a
    stack-based out-of-bounds write because an empty
    nodelist is mishandled during mount option parsing, aka
    CID-aa9f7d5172fa.(CVE-2020-11565)

  - An issue was discovered in slc_bump in
    drivers/net/can/slcan.c in the Linux kernel through
    5.6.2. It allows attackers to read uninitialized
    can_frame data, potentially containing sensitive
    information from kernel stack memory, if the
    configuration lacks CONFIG_INIT_STACK_ALL, aka
    CID-b9258a2cece4.(CVE-2020-11494)

  - btrfs_root_node in fs/btrfs/ctree.c in the Linux kernel
    through 5.3.12 allows a NULL pointer dereference
    because rcu_dereference(root->node) can be
    zero.(CVE-2019-19036)

  - ext4_empty_dir in fs/ext4/namei.c in the Linux kernel
    through 5.3.12 allows a NULL pointer dereference
    because ext4_read_dirblock(inode,0,DIRENT_HTREE) can be
    zero.(CVE-2019-19037)

  - __btrfs_free_extent in fs/btrfs/extent-tree.c in the
    Linux kernel through 5.3.12 calls btrfs_print_leaf in a
    certain ENOENT case, which allows local users to obtain
    potentially sensitive information about register values
    via the dmesg program.(CVE-2019-19039)

  - In the Linux kernel 5.0.21, mounting a crafted f2fs
    filesystem image can cause a NULL pointer dereference
    in f2fs_recover_fsync_data in fs/f2fs/recovery.c. This
    is related to F2FS_P_SB in
    fs/f2fs/f2fs.h.(CVE-2019-19815)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1508
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d1bbee1a");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-20636");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-1749");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/20");

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

pkgs = ["bpftool-4.19.36-vhulk1907.1.0.h729.eulerosv2r8",
        "kernel-4.19.36-vhulk1907.1.0.h729.eulerosv2r8",
        "kernel-devel-4.19.36-vhulk1907.1.0.h729.eulerosv2r8",
        "kernel-headers-4.19.36-vhulk1907.1.0.h729.eulerosv2r8",
        "kernel-source-4.19.36-vhulk1907.1.0.h729.eulerosv2r8",
        "kernel-tools-4.19.36-vhulk1907.1.0.h729.eulerosv2r8",
        "kernel-tools-libs-4.19.36-vhulk1907.1.0.h729.eulerosv2r8",
        "perf-4.19.36-vhulk1907.1.0.h729.eulerosv2r8",
        "python-perf-4.19.36-vhulk1907.1.0.h729.eulerosv2r8",
        "python3-perf-4.19.36-vhulk1907.1.0.h729.eulerosv2r8"];

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
