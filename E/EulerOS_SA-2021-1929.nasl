#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150214);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/07");

  script_cve_id(
    "CVE-2020-0465",
    "CVE-2020-16120",
    "CVE-2020-25639",
    "CVE-2021-27363",
    "CVE-2021-27364",
    "CVE-2021-27365",
    "CVE-2021-3347",
    "CVE-2021-3348"
  );

  script_name(english:"EulerOS 2.0 SP9 : kernel (EulerOS-SA-2021-1929)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - An issue was discovered in the Linux kernel through
    5.11.3. A kernel pointer leak can be used to determine
    the address of the iscsi_transport structure. When an
    iSCSI transport is registered with the iSCSI subsystem,
    the transport's handle is available to unprivileged
    users via the sysfs file system, at
    /sys/class/iscsi_transport/$TRANSPORT_NAME/handle. When
    read, the show_transport_handle function (in
    drivers/scsi/scsi_transport_iscsi.c) is called, which
    leaks the handle. This handle is actually the pointer
    to an iscsi_transport struct in the kernel module's
    global variables.(CVE-2021-27363)

  - An issue was discovered in the Linux kernel through
    5.11.3. Certain iSCSI data structures do not have
    appropriate length constraints or checks, and can
    exceed the PAGE_SIZE value. An unprivileged user can
    send a Netlink message that is associated with iSCSI,
    and has a length up to the maximum length of a Netlink
    message.(CVE-2021-27365)

  - An issue was discovered in the Linux kernel through
    5.11.3. drivers/scsi/scsi_transport_iscsi.c is
    adversely affected by the ability of an unprivileged
    user to craft Netlink messages.(CVE-2021-27364)

  - A NULL pointer dereference flaw was found in the Linux
    kernel's GPU Nouveau driver functionality in versions
    prior to 5.12-rc1 in the way the user calls ioctl
    DRM_IOCTL_NOUVEAU_CHANNEL_ALLOC. This flaw allows a
    local user to crash the system.(CVE-2020-25639)

  - Overlayfs did not properly perform permission checking
    when copying up files in an overlayfs and could be
    exploited from within a user namespace, if, for
    example, unprivileged user namespaces were allowed. It
    was possible to have a file not readable by an
    unprivileged user to be copied to a mountpoint
    controlled by the user, like a removable device. This
    was introduced in kernel version 4.19 by commit d1d04ef
    ('ovl: stack file ops'). This was fixed in kernel
    version 5.8 by commits 56230d9 ('ovl: verify
    permissions in ovl_path_open()'), 48bd024 ('ovl: switch
    to mounter creds in readdir') and 05acefb ('ovl: check
    permission to open real file'). Additionally, commits
    130fdbc ('ovl: pass correct flags for opening real
    directory') and 292f902 ('ovl: call secutiry hook in
    ovl_real_ioctl()') in kernel 5.8 might also be desired
    or necessary. These additional commits introduced a
    regression in overlay mounts within user namespaces
    which prevented access to files with ownership outside
    of the user namespace. This regression was mitigated by
    subsequent commit b6650da ('ovl: do not fail because of
    O_NOATIMEi') in kernel 5.11.(CVE-2020-16120)

  - In various methods of hid-multitouch.c, there is a
    possible out of bounds write due to a missing bounds
    check. This could lead to local escalation of privilege
    with no additional execution privileges needed. User
    interaction is not needed for exploitation.Product:
    AndroidVersions: Android kernelAndroid ID:
    A-162844689References: Upstream kernel(CVE-2020-0465)

  - nbd_add_socket in drivers/block/nbd.c in the Linux
    kernel through 5.10.12 has an ndb_queue_rq
    use-after-free that could be triggered by local
    attackers (with access to the nbd device) via an I/O
    request at a certain point during device setup, aka
    CID-b98e762e3d71.(CVE-2021-3348)

  - An issue was discovered in the Linux kernel through
    5.10.11. PI futexes have a kernel stack use-after-free
    during fault handling, allowing local users to execute
    code in the kernel, aka
    CID-34b1a1ce1458.(CVE-2021-3347)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1929
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29dd596c");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3347");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(9)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-4.18.0-147.5.1.6.h425.eulerosv2r9",
        "kernel-tools-4.18.0-147.5.1.6.h425.eulerosv2r9",
        "kernel-tools-libs-4.18.0-147.5.1.6.h425.eulerosv2r9",
        "python3-perf-4.18.0-147.5.1.6.h425.eulerosv2r9"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"9", reference:pkg)) flag++;

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
