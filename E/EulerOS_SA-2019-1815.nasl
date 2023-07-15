#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(128184);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2018-16867",
    "CVE-2018-16872",
    "CVE-2018-19364",
    "CVE-2018-19489",
    "CVE-2018-20191",
    "CVE-2019-3812",
    "CVE-2019-6778"
  );

  script_name(english:"EulerOS 2.0 SP8 : qemu-kvm (EulerOS-SA-2019-1815)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the qemu-kvm packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A flaw was found in QEMU's Media Transfer Protocol
    (MTP) where a path traversal in the in
    usb_mtp_write_data function in hw/usb/dev-mtp.c due to
    an improper file name sanitization. Reading and writing
    of arbitrary files is allowed when a guest device is
    mounted which may lead to a denial of service scenario
    or possibly lead to code execution on the
    host.(CVE-2018-16867)

  - A flaw was found in QEMU's Media Transfer Protocol
    (MTP). The code opening files in usb_mtp_get_object and
    usb_mtp_get_partial_object and directories in
    usb_mtp_object_readdir doesn't consider that the
    underlying filesystem may have changed since the time
    lstat(2) was called in usb_mtp_object_alloc, a
    classical TOCTTOU problem. An attacker with write
    access to the host filesystem, shared with a guest, can
    use this property to navigate the host filesystem in
    the context of the QEMU process and read any file the
    QEMU process has access to. Access to the filesystem
    may be local or via a network share protocol such as
    CIFS.(CVE-2018-16872)

  - hw/9pfs/cofile.c and hw/9pfs/9p.c in QEMU can modify an
    fid path while it is being accessed by a second thread,
    leading to (for example) a use-after-free
    outcome.(CVE-2018-19364)

  - v9fs_wstat in hw/9pfs/9p.c in QEMU allows guest OS
    users to cause a denial of service (crash) because of a
    race condition during file renaming.(CVE-2018-19489)

  - hw/rdma/vmw/pvrdma_main.c in QEMU does not implement a
    read operation (such as uar_read by analogy to
    uar_write), which allows attackers to cause a denial of
    service (NULL pointer dereference).(CVE-2018-20191)

  - QEMU, through version 2.10 and through version 3.1.0,
    is vulnerable to an out-of-bounds read of up to 128
    bytes in the hw/i2c/i2c-ddc.c:i2c_ddc() function. A
    local attacker with permission to execute i2c commands
    could exploit this to read stack memory of the qemu
    process on the host.(CVE-2019-3812)

  - In QEMU 3.0.0, tcp_emu in slirp/tcp_subr.c has a
    heap-based buffer overflow.(CVE-2019-6778)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1815
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9661b617");
  script_set_attribute(attribute:"solution", value:
"Update the affected qemu-kvm packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6778");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-audio-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-audio-oss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-audio-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-audio-sdl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-block-dmg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-block-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-block-nfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-block-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-system-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-system-aarch64-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-ui-curses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-ui-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-ui-sdl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["qemu-audio-alsa-3.0.0-4.h1.eulerosv2r8",
        "qemu-audio-oss-3.0.0-4.h1.eulerosv2r8",
        "qemu-audio-pa-3.0.0-4.h1.eulerosv2r8",
        "qemu-audio-sdl-3.0.0-4.h1.eulerosv2r8",
        "qemu-block-curl-3.0.0-4.h1.eulerosv2r8",
        "qemu-block-dmg-3.0.0-4.h1.eulerosv2r8",
        "qemu-block-gluster-3.0.0-4.h1.eulerosv2r8",
        "qemu-block-iscsi-3.0.0-4.h1.eulerosv2r8",
        "qemu-block-nfs-3.0.0-4.h1.eulerosv2r8",
        "qemu-block-rbd-3.0.0-4.h1.eulerosv2r8",
        "qemu-block-ssh-3.0.0-4.h1.eulerosv2r8",
        "qemu-common-3.0.0-4.h1.eulerosv2r8",
        "qemu-img-3.0.0-4.h1.eulerosv2r8",
        "qemu-kvm-3.0.0-4.h1.eulerosv2r8",
        "qemu-system-aarch64-3.0.0-4.h1.eulerosv2r8",
        "qemu-system-aarch64-core-3.0.0-4.h1.eulerosv2r8",
        "qemu-ui-curses-3.0.0-4.h1.eulerosv2r8",
        "qemu-ui-gtk-3.0.0-4.h1.eulerosv2r8",
        "qemu-ui-sdl-3.0.0-4.h1.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-kvm");
}
