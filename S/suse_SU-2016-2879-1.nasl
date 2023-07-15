#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2879-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(95283);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2016-7161", "CVE-2016-7170", "CVE-2016-7422", "CVE-2016-7466", "CVE-2016-7907", "CVE-2016-7908", "CVE-2016-7909", "CVE-2016-7994", "CVE-2016-7995", "CVE-2016-8576", "CVE-2016-8577", "CVE-2016-8578", "CVE-2016-8667", "CVE-2016-8668", "CVE-2016-8669", "CVE-2016-8909", "CVE-2016-8910", "CVE-2016-9101", "CVE-2016-9104", "CVE-2016-9105", "CVE-2016-9106");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : qemu (SUSE-SU-2016:2879-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for qemu to version 2.6.2 fixes the several issues. These
security issues were fixed :

  - CVE-2016-7161: Heap-based buffer overflow in the
    .receive callback of xlnx.xps-ethernetlite in QEMU (aka
    Quick Emulator) allowed attackers to execute arbitrary
    code on the QEMU host via a large ethlite packet
    (bsc#1001151).

  - CVE-2016-7170: OOB stack memory access when processing
    svga command (bsc#998516).

  - CVE-2016-7466: xhci memory leakage during device unplug
    (bsc#1000345).

  - CVE-2016-7422: NULL pointer dereference in
    virtqueu_map_desc (bsc#1000346).

  - CVE-2016-7908: The mcf_fec_do_tx function in
    hw/net/mcf_fec.c did not properly limit the buffer
    descriptor count when transmitting packets, which
    allowed local guest OS administrators to cause a denial
    of service (infinite loop and QEMU process crash) via
    vectors involving a buffer descriptor with a length of 0
    and crafted values in bd.flags (bsc#1002550).

  - CVE-2016-7995: Memory leak in ehci_process_itd
    (bsc#1003612).

  - CVE-2016-8576: The xhci_ring_fetch function in
    hw/usb/hcd-xhci.c allowed local guest OS administrators
    to cause a denial of service (infinite loop and QEMU
    process crash) by leveraging failure to limit the number
    of link Transfer Request Blocks (TRB) to process
    (bsc#1003878).

  - CVE-2016-8578: The v9fs_iov_vunmarshal function in
    fsdev/9p-iov-marshal.c allowed local guest OS
    administrators to cause a denial of service (NULL
    pointer dereference and QEMU process crash) by sending
    an empty string parameter to a 9P operation
    (bsc#1003894).

  - CVE-2016-9105: Memory leakage in v9fs_link
    (bsc#1007494).

  - CVE-2016-8577: Memory leak in the v9fs_read function in
    hw/9pfs/9p.c allowed local guest OS administrators to
    cause a denial of service (memory consumption) via
    vectors related to an I/O read operation (bsc#1003893).

  - CVE-2016-9106: Memory leakage in v9fs_write
    (bsc#1007495).

  - CVE-2016-8669: The serial_update_parameters function in
    hw/char/serial.c allowed local guest OS administrators
    to cause a denial of service (divide-by-zero error and
    QEMU process crash) via vectors involving a value of
    divider greater than baud base (bsc#1004707).

  - CVE-2016-7909: The pcnet_rdra_addr function in
    hw/net/pcnet.c allowed local guest OS administrators to
    cause a denial of service (infinite loop and QEMU
    process crash) by setting the (1) receive or (2)
    transmit descriptor ring length to 0 (bsc#1002557).

  - CVE-2016-9101: eepro100 memory leakage whern unplugging
    a device (bsc#1007391).

  - CVE-2016-8668: The rocker_io_writel function in
    hw/net/rocker/rocker.c allowed local guest OS
    administrators to cause a denial of service
    (out-of-bounds read and QEMU process crash) by
    leveraging failure to limit DMA buffer size
    (bsc#1004706).

  - CVE-2016-8910: The rtl8139_cplus_transmit function in
    hw/net/rtl8139.c allowed local guest OS administrators
    to cause a denial of service (infinite loop and CPU
    consumption) by leveraging failure to limit the ring
    descriptor count (bsc#1006538).

  - CVE-2016-8909: The intel_hda_xfer function in
    hw/audio/intel-hda.c allowed local guest OS
    administrators to cause a denial of service (infinite
    loop and CPU consumption) via an entry with the same
    value for buffer length and pointer position
    (bsc#1006536).

  - CVE-2016-7994: Memory leak in
    virtio_gpu_resource_create_2d (bsc#1003613).

  - CVE-2016-9104: Integer overflow leading to OOB access in
    9pfs (bsc#1007493).

  - CVE-2016-8667: The rc4030_write function in
    hw/dma/rc4030.c allowed local guest OS administrators to
    cause a denial of service (divide-by-zero error and QEMU
    process crash) via a large interval timer reload value
    (bsc#1004702).

  - CVE-2016-7907: The pcnet_rdra_addr function in
    hw/net/pcnet.c allowed local guest OS administrators to
    cause a denial of service (infinite loop and QEMU
    process crash) by setting the (1) receive or (2)
    transmit descriptor ring length to 0 (bsc#1002549).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1000345"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1000346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1001151"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1002116"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1002549"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1002550"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1002557"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1003612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1003613"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1003878"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1003893"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1003894"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1004702"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1004706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1004707"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1005353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1005374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1006536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1006538"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1007263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1007391"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1007493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1007494"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1007495"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1007769"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1008148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=998516"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7161/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7170/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7422/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7466/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7907/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7908/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7909/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7994/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7995/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8576/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8577/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8578/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8667/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8668/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8669/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8909/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8910/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9101/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9104/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9105/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9106/"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162879-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9f9c4fc2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2016-1682=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2016-1682=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2016-1682=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-ssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-guest-agent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-x86");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"qemu-2.6.2-31.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"qemu-block-curl-2.6.2-31.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"qemu-block-curl-debuginfo-2.6.2-31.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"qemu-block-ssh-2.6.2-31.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"qemu-block-ssh-debuginfo-2.6.2-31.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"qemu-debugsource-2.6.2-31.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"qemu-guest-agent-2.6.2-31.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"qemu-guest-agent-debuginfo-2.6.2-31.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"qemu-lang-2.6.2-31.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"qemu-tools-2.6.2-31.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"qemu-tools-debuginfo-2.6.2-31.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"qemu-block-rbd-2.6.2-31.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"qemu-block-rbd-debuginfo-2.6.2-31.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"qemu-kvm-2.6.2-31.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"qemu-x86-2.6.2-31.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"qemu-2.6.2-31.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"qemu-block-curl-2.6.2-31.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"qemu-block-curl-debuginfo-2.6.2-31.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"qemu-debugsource-2.6.2-31.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"qemu-kvm-2.6.2-31.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"qemu-tools-2.6.2-31.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"qemu-tools-debuginfo-2.6.2-31.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"qemu-x86-2.6.2-31.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu");
}
