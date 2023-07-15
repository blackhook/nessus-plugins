#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(139983);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2018-16847",
    "CVE-2018-20125",
    "CVE-2018-20216",
    "CVE-2018-7550",
    "CVE-2019-12155",
    "CVE-2019-12247",
    "CVE-2019-13164",
    "CVE-2019-14378",
    "CVE-2019-20175",
    "CVE-2019-5008",
    "CVE-2020-7211"
  );

  script_name(english:"EulerOS 2.0 SP8 : qemu (EulerOS-SA-2020-1880)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the qemu package installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - tftp.c in libslirp 4.1.0, as used in QEMU 4.2.0, does
    not prevent ..\ directory traversal on
    Windows.(CVE-2020-7211)

  - interface_release_resource in hw/display/qxl.c in QEMU
    4.0.0 has a NULL pointer dereference.(CVE-2019-12155)

  - QEMU 3.0.0 has an Integer Overflow because the
    qga/commands*.c files do not check the length of the
    argument list or the number of environment variables.
    NOTE: This has been disputed as not
    exploitable.(CVE-2019-12247)

  - qemu-bridge-helper.c in QEMU 4.0.0 does not ensure that
    a network interface name (obtained from bridge.conf or
    a --br=bridge option) is limited to the IFNAMSIZ size,
    which can lead to an ACL bypass.(CVE-2019-13164)

  - ip_reass in ip_input.c in libslirp 4.0.0 has a
    heap-based buffer overflow via a large packet because
    it mishandles a case involving the first
    fragment.(CVE-2019-14378)

  - An issue was discovered in ide_dma_cb() in
    hw/ide/core.c in QEMU 2.4.0 through 4.2.0. The guest
    system can crash the QEMU process in the host system
    via a special SCSI_IOCTL_SEND_COMMAND. It hits an
    assertion that implies that the size of successful DMA
    transfers there must be a multiple of 512 (the size of
    a sector). NOTE: a member of the QEMU security team
    disputes the significance of this issue because a
    'privileged guest user has many ways to cause similar
    DoS effect, without triggering this
    assert.'(CVE-2019-20175)

  - hw/sparc64/sun4u.c in QEMU 3.1.50 is vulnerable to a
    NULL pointer dereference, which allows the attacker to
    cause a denial of service via a device
    driver.(CVE-2019-5008)

  - An OOB heap buffer r/w access issue was found in the
    NVM Express Controller emulation in QEMU. It could
    occur in nvme_cmb_ops routines in nvme device. A guest
    user/process could use this flaw to crash the QEMU
    process resulting in DoS or potentially run arbitrary
    code with privileges of the QEMU
    process.(CVE-2018-16847)

  - hw/rdma/vmw/pvrdma_cmd.c in QEMU allows attackers to
    cause a denial of service (NULL pointer dereference or
    excessive memory allocation) in create_cq_ring or
    create_qp_rings.(CVE-2018-20125)

  - QEMU can have an infinite loop in
    hw/rdma/vmw/pvrdma_dev_ring.c because return values are
    not checked (and -1 is mishandled).(CVE-2018-20216)

  - The load_multiboot function in hw/i386/multiboot.c in
    Quick Emulator (aka QEMU) allows local guest OS users
    to execute arbitrary code on the QEMU host via a
    mh_load_end_addr value greater than mh_bss_end_addr,
    which triggers an out-of-bounds read or write memory
    access.(CVE-2018-7550)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1880
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?321adce4");
  script_set_attribute(attribute:"solution", value:
"Update the affected qemu packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-img");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["qemu-img-3.0.1-3.h6.eulerosv2r8"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu");
}
