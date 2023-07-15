#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110865);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-13672",
    "CVE-2017-13711",
    "CVE-2017-15124",
    "CVE-2017-15268",
    "CVE-2018-3639",
    "CVE-2018-5683",
    "CVE-2018-7858"
  );

  script_name(english:"EulerOS 2.0 SP3 : qemu-kvm (EulerOS-SA-2018-1201)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the qemu-kvm packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - QEMU (aka Quick Emulator), when built with the VGA
    display emulator support, allows local guest OS
    privileged users to cause a denial of service
    (out-of-bounds read and QEMU process crash) via vectors
    involving display update.(CVE-2017-13672)

  - Use-after-free vulnerability in the sofree function in
    slirp/socket.c in QEMU (aka Quick Emulator) allows
    attackers to cause a denial of service (QEMU instance
    crash) by leveraging failure to properly clear ifq_so
    from pending packets.(CVE-2017-13711)

  - VNC server implementation in Quick Emulator (QEMU)
    2.11.0 and older was found to be vulnerable to an
    unbounded memory allocation issue, as it did not
    throttle the framebuffer updates sent to its client. If
    the client did not consume these updates, VNC server
    allocates growing memory to hold onto this data. A
    malicious remote VNC client could use this flaw to
    cause DoS to the server host.(CVE-2017-15124)

  - Qemu through 2.10.0 allows remote attackers to cause a
    memory leak by triggering slow data-channel read
    operations, related to
    io/channel-websock.c.(CVE-2017-15268)

  - The vga_draw_text function in Qemu allows local OS
    guest privileged users to cause a denial of service
    (out-of-bounds read and QEMU process crash) by
    leveraging improper memory address
    validation.(CVE-2018-5683)

  - An industry-wide issue was found in the way many modern
    microprocessor designs have implemented speculative
    execution of Load i1/4+ Store instructions (a commonly
    used performance optimization). It relies on the
    presence of a precisely-defined instruction sequence in
    the privileged code as well as the fact that memory
    read from address to which a recent memory write has
    occurred may see an older value and subsequently cause
    an update into the microprocessor's data cache even for
    speculatively executed instructions that never actually
    commit (retire). As a result, an unprivileged attacker
    could use this flaw to read privileged memory by
    conducting targeted cache side-channel attacks.
    (CVE-2018-3639)

  - Quick Emulator (aka QEMU), when built with the Cirrus
    CLGD 54xx VGA Emulator support, allows local guest OS
    privileged users to cause a denial of service
    (out-of-bounds access and QEMU process crash) by
    leveraging incorrect region calculation when updating
    VGA display.(CVE-2018-7858)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1201
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f82cacb");
  script_set_attribute(attribute:"solution", value:
"Update the affected qemu-kvm packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["qemu-img-1.5.3-156.2.h2",
        "qemu-kvm-1.5.3-156.2.h2",
        "qemu-kvm-common-1.5.3-156.2.h2"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-kvm");
}
