#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124908);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id(
    "CVE-2016-9602",
    "CVE-2017-5579",
    "CVE-2017-8284",
    "CVE-2017-8379",
    "CVE-2017-9330",
    "CVE-2017-9373",
    "CVE-2017-13672",
    "CVE-2017-13673",
    "CVE-2017-14167",
    "CVE-2017-15119",
    "CVE-2017-15124",
    "CVE-2017-15268",
    "CVE-2017-18043",
    "CVE-2018-7550",
    "CVE-2018-10839",
    "CVE-2018-12617"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : qemu-kvm (EulerOS-SA-2019-1405)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the qemu-kvm packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - An integer overflow issue was found in the NE200 NIC
    emulation. It could occur while receiving packets from
    the network, if the size value was greater than
    INT_MAX. Such overflow would lead to stack buffer
    overflow issue. A user inside guest could use this flaw
    to crash the QEMU process, resulting in DoS scenario.
    (CVE-2018-10839)

  - qmp_guest_file_read in qga/commands-posix.c and
    qga/commands-win32.c in qemu-ga (aka QEMU Guest Agent)
    in QEMU 2.12.50 has an integer overflow causing a
    g_malloc0() call to trigger a segmentation fault when
    trying to allocate a large memory chunk. The
    vulnerability can be exploited by sending a crafted QMP
    command (including guest-file-read with a large count
    value) to the agent via the listening
    socket.(CVE-2018-12617)

  - Qemu before version 2.9 is vulnerable to an improper
    link following when built with the VirtFS. A privileged
    user inside guest could use this flaw to access host
    file system beyond the shared folder and potentially
    escalating their privileges on a host. (CVE-2016-9602)

  - Quick Emulator (QEMU), compiled with the PC System
    Emulator with multiboot feature support, is vulnerable
    to an OOB r/w memory access issue. The issue could
    occur while loading a kernel image during the guest
    boot, if mh_load_end_addr address is greater than the
    mh_bss_end_addr address. A user or process could use
    this flaw to potentially achieve arbitrary code
    execution on a host.(CVE-2018-7550)

  - An out-of-bounds read access issue was found in the VGA
    display emulator built into the Quick emulator (QEMU).
    It could occur while reading VGA memory to update
    graphics display. A privileged user/process inside
    guest could use this flaw to crash the QEMU process on
    the host resulting in denial of service
    situation.(CVE-2017-13672)

  - An assert failure issue was found in the VGA display
    emulator built into the Quick emulator (QEMU). It could
    occur while updating graphics display, due to
    miscalculating region for dirty bitmap snapshot in
    split screen mode. A privileged user/process inside
    guest could use this flaw to crash the QEMU process on
    the host resulting in denial of service.
    (CVE-2017-13673)

  - The Network Block Device (NBD) server in Quick Emulator
    (QEMU), is vulnerable to a denial of service issue. It
    could occur if a client sent large option requests,
    making the server waste CPU time on reading up to 4GB
    per request. A client could use this flaw to keep the
    NBD server from serving other requests, resulting in
    DoS.(CVE-2017-15119)

  - QEMU (aka Quick Emulator) before 2.9.0, when built with
    the USB OHCI Emulation support, allows local guest OS
    users to cause a denial of service (infinite loop) by
    leveraging an incorrect return value, a different
    vulnerability than CVE-2017-6505.(CVE-2017-9330)

  - Integer overflow in the macro ROUND_UP (n, d) in Quick
    Emulator (Qemu) allows a user to cause a denial of
    service (Qemu process crash). (CVE-2017-18043)

  - VNC server implementation in Quick Emulator (QEMU) was
    found to be vulnerable to an unbounded memory
    allocation issue, as it did not throttle the
    framebuffer updates sent to its client. If the client
    did not consume these updates, VNC server allocates
    growing memory to hold onto this data. A malicious
    remote VNC client could use this flaw to cause DoS to
    the server host.(CVE-2017-15124)

  - A memory leakage issue was found in the I/O channels
    websockets implementation of the Quick Emulator (QEMU).
    It could occur while sending screen updates to a
    client, which is slow to read and process them further.
    A privileged guest user could use this flaw to cause a
    denial of service on the host and/or potentially crash
    the QEMU process instance on the host.(CVE-2017-15268)

  - Quick Emulator (QEMU), compiled with the PC System
    Emulator with multiboot feature support, is vulnerable
    to an OOB r/w memory access issue. The issue could
    occur due to an integer overflow while loading a kernel
    image during a guest boot. A user or process could use
    this flaw to potentially achieve arbitrary code
    execution on a host.(CVE-2017-14167)

  - Memory leak in QEMU (aka Quick Emulator), when built
    with IDE AHCI Emulation support, allows local guest OS
    privileged users to cause a denial of service (memory
    consumption) by repeatedly hot-unplugging the AHCI
    device.(CVE-2017-9373)

  - Memory leak in the serial_exit_core function in
    hw/char/serial.c in QEMU (aka Quick Emulator) allows
    local guest OS privileged users to cause a denial of
    service (host memory consumption and QEMU process
    crash) via a large number of device unplug
    operations.(CVE-2017-5579)

  - ** DISPUTED ** The disas_insn function in
    target/i386/translate.c in QEMU before 2.9.0, when TCG
    mode without hardware acceleration is used, does not
    limit the instruction size, which allows local users to
    gain privileges by creating a modified basic block that
    injects code into a setuid program, as demonstrated by
    procmail. NOTE: the vendor has stated 'this bug does
    not violate any security guarantees QEMU
    makes.'(CVE-2017-8284)

  - Memory leak in the keyboard input event handlers
    support in QEMU (aka Quick Emulator) allows local guest
    OS privileged users to cause a denial of service (host
    memory consumption) by rapidly generating large
    keyboard events.(CVE-2017-8379)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1405
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?21fa9e3c");
  script_set_attribute(attribute:"solution", value:
"Update the affected qemu-kvm packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-9602");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-7550");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["qemu-img-2.8.1-30.025",
        "qemu-kvm-2.8.1-30.025",
        "qemu-kvm-common-2.8.1-30.025",
        "qemu-kvm-tools-2.8.1-30.025"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
