#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105046);
  script_version("3.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-1000410",
    "CVE-2017-12190",
    "CVE-2017-12193",
    "CVE-2017-15102",
    "CVE-2017-15115"
  );

  script_name(english:"EulerOS 2.0 SP1 : kernel (EulerOS-SA-2017-1318)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A flaw was found in the processing of incoming L2CAP
    bluetooth commands. Uninitialized stack variables can
    be sent to an attacker leaking data in kernel address
    space.(CVE-2017-1000410)

  - The assoc_array_insert_into_terminal_node function in
    lib/assoc_array.c in the Linux kernel before 4.13.11
    mishandles node splitting, which allows local users to
    cause a denial of service (NULL pointer dereference and
    panic) via a crafted application, as demonstrated by
    the keyring key type, and key addition and link
    creation operations.(CVE-2017-12193)

  - The bio_map_user_iov and bio_unmap_user functions in
    block/bio.c in the Linux kernel before 4.13.8 do
    unbalanced refcounting when a SCSI I/O vector has small
    consecutive buffers belonging to the same page. The
    bio_add_pc_page function merges them into one, but the
    page reference is never dropped. This causes a memory
    leak and possible system lockup (exploitable against
    the host OS by a guest OS user, if a SCSI disk is
    passed through to a virtual machine) due to an
    out-of-memory condition.(CVE-2017-12190)

  - The tower_probe function in
    drivers/usb/misc/legousbtower.c in the Linux kernel
    before 4.8.1 allows local users (who are physically
    proximate for inserting a crafted USB device) to gain
    privileges by leveraging a write-what-where condition
    that occurs after a race condition and a NULL pointer
    dereference.(CVE-2017-15102)

  - The sctp_do_peeloff function in net/sctp/socket.c in
    the Linux kernel before 4.14 does not check whether the
    intended netns is used in a peel-off action, which
    allows local users to cause a denial of service
    (use-after-free and system crash) or possibly have
    unspecified other impact via crafted system
    calls.(CVE-2017-15115)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1318
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e1964858");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(1)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-229.49.1.157",
        "kernel-debug-3.10.0-229.49.1.157",
        "kernel-debuginfo-3.10.0-229.49.1.157",
        "kernel-debuginfo-common-x86_64-3.10.0-229.49.1.157",
        "kernel-devel-3.10.0-229.49.1.157",
        "kernel-headers-3.10.0-229.49.1.157",
        "kernel-tools-3.10.0-229.49.1.157",
        "kernel-tools-libs-3.10.0-229.49.1.157",
        "perf-3.10.0-229.49.1.157",
        "python-perf-3.10.0-229.49.1.157"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"1", reference:pkg)) flag++;

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
