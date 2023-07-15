#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(147128);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/08");

  script_cve_id(
    "CVE-2017-9524",
    "CVE-2020-10756",
    "CVE-2020-12829",
    "CVE-2020-25723"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.6.0 : qemu-kvm (EulerOS-SA-2021-1527)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the qemu-kvm packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - An out-of-bounds read vulnerability was found in the
    SLiRP networking implementation of the QEMU emulator.
    This flaw occurs in the icmp6_send_echoreply() routine
    while replying to an ICMP echo request, also known as
    ping. This flaw allows a malicious guest to leak the
    contents of the host memory, resulting in possible
    information disclosure. This flaw affects versions of
    libslirp before 4.3.1.(CVE-2020-10756)

  - In QEMU through 5.0.0, an integer overflow was found in
    the SM501 display driver implementation. This flaw
    occurs in the COPY_AREA macro while handling MMIO write
    operations through the sm501_2d_engine_write()
    callback. A local attacker could abuse this flaw to
    crash the QEMU process in sm501_2d_operation() in
    hw/display/sm501.c on the host, resulting in a denial
    of service.(CVE-2020-12829)

  - Quick Emulator (QEMU) built with Network Block Device
    (NBD) Server support was vulnerable to a null-pointer
    dereference issue. The flaw could occur when releasing
    a client that was not initialized due to failed
    negotiation. A remote user or process could exploit
    this flaw to crash the qemu-nbd server (denial of
    service).(CVE-2017-9524)

  - A reachable assertion issue was found in the USB EHCI
    emulation code of QEMU. It could occur while processing
    USB requests due to missing handling of DMA memory map
    failure. A malicious privileged user within the guest
    may abuse this flaw to send bogus USB requests and
    crash the QEMU process on the host, resulting in a
    denial of service.(CVE-2020-25723)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1527
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f3afaf7");
  script_set_attribute(attribute:"solution", value:
"Update the affected qemu-kvm packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10756");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["qemu-img-2.8.1-30.465",
        "qemu-kvm-2.8.1-30.465",
        "qemu-kvm-common-2.8.1-30.465",
        "qemu-kvm-tools-2.8.1-30.465"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
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
