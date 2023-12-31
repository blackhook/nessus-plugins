#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2589-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(94277);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2016-2391", "CVE-2016-2392", "CVE-2016-4453", "CVE-2016-4454", "CVE-2016-5105", "CVE-2016-5106", "CVE-2016-5107", "CVE-2016-5126", "CVE-2016-5238", "CVE-2016-5337", "CVE-2016-5338", "CVE-2016-5403", "CVE-2016-6490", "CVE-2016-6833", "CVE-2016-6836", "CVE-2016-6888", "CVE-2016-7116", "CVE-2016-7155", "CVE-2016-7156");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : qemu (SUSE-SU-2016:2589-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"qemu was updated to fix 19 security issues. These security issues were
fixed :

  - CVE-2016-2392: The is_rndis function in the USB Net
    device emulator (hw/usb/dev-network.c) in QEMU did not
    properly validate USB configuration descriptor objects,
    which allowed local guest OS administrators to cause a
    denial of service (NULL pointer dereference and QEMU
    process crash) via vectors involving a remote NDIS
    control message packet (bsc#967012)

  - CVE-2016-2391: The ohci_bus_start function in the USB
    OHCI emulation support (hw/usb/hcd-ohci.c) in QEMU
    allowed local guest OS administrators to cause a denial
    of service (NULL pointer dereference and QEMU process
    crash) via vectors related to multiple eof_timers
    (bsc#967013)

  - CVE-2016-5106: The megasas_dcmd_set_properties function
    in hw/scsi/megasas.c in QEMU, when built with MegaRAID
    SAS 8708EM2 Host Bus Adapter emulation support, allowed
    local guest administrators to cause a denial of service
    (out-of-bounds write access) via vectors involving a
    MegaRAID Firmware Interface (MFI) command (bsc#982018)

  - CVE-2016-5105: The megasas_dcmd_cfg_read function in
    hw/scsi/megasas.c in QEMU, when built with MegaRAID SAS
    8708EM2 Host Bus Adapter emulation support, used an
    uninitialized variable, which allowed local guest
    administrators to read host memory via vectors involving
    a MegaRAID Firmware Interface (MFI) command (bsc#982017)

  - CVE-2016-5107: The megasas_lookup_frame function in
    QEMU, when built with MegaRAID SAS 8708EM2 Host Bus
    Adapter emulation support, allowed local guest OS
    administrators to cause a denial of service
    (out-of-bounds read and crash) via unspecified vectors
    (bsc#982019)

  - CVE-2016-5126: Heap-based buffer overflow in the
    iscsi_aio_ioctl function in block/iscsi.c in QEMU
    allowed local guest OS users to cause a denial of
    service (QEMU process crash) or possibly execute
    arbitrary code via a crafted iSCSI asynchronous I/O
    ioctl call (bsc#982285)

  - CVE-2016-4454: The vmsvga_fifo_read_raw function in
    hw/display/vmware_vga.c in QEMU allowed local guest OS
    administrators to obtain sensitive host memory
    information or cause a denial of service (QEMU process
    crash) by changing FIFO registers and issuing a VGA
    command, which triggers an out-of-bounds read
    (bsc#982222)

  - CVE-2016-4453: The vmsvga_fifo_run function in
    hw/display/vmware_vga.c in QEMU allowed local guest OS
    administrators to cause a denial of service (infinite
    loop and QEMU process crash) via a VGA command
    (bsc#982223)

  - CVE-2016-5338: The (1) esp_reg_read and (2)
    esp_reg_write functions in hw/scsi/esp.c in QEMU allowed
    local guest OS administrators to cause a denial of
    service (QEMU process crash) or execute arbitrary code
    on the QEMU host via vectors related to the information
    transfer buffer (bsc#983982)

  - CVE-2016-5337: The megasas_ctrl_get_info function in
    hw/scsi/megasas.c in QEMU allowed local guest OS
    administrators to obtain sensitive host memory
    information via vectors related to reading device
    control information (bsc#983961)

  - CVE-2016-5238: The get_cmd function in hw/scsi/esp.c in
    QEMU allowed local guest OS administrators to cause a
    denial of service (out-of-bounds write and QEMU process
    crash) via vectors related to reading from the
    information transfer buffer in non-DMA mode (bsc#982959)

  - CVE-2016-5403: The virtqueue_pop function in
    hw/virtio/virtio.c in QEMU allowed local guest OS
    administrators to cause a denial of service (memory
    consumption and QEMU process crash) by submitting
    requests without waiting for completion (bsc#991080)

  - CVE-2016-6490: Infinite loop in the virtio framework. A
    privileged user inside the guest could have used this
    flaw to crash the Qemu instance on the host resulting in
    DoS (bsc#991466)

  - CVE-2016-6888: Integer overflow in packet initialisation
    in VMXNET3 device driver. A privileged user inside guest
    could have used this flaw to crash the Qemu instance
    resulting in DoS (bsc#994771)

  - CVE-2016-6833: Use-after-free issue in the VMWARE
    VMXNET3 NIC device support. A privileged user inside
    guest could have used this issue to crash the Qemu
    instance resulting in DoS (bsc#994774)

  - CVE-2016-7116: Host directory sharing via Plan 9 File
    System(9pfs) was vulnerable to a directory/path
    traversal issue. A privileged user inside guest could
    have used this flaw to access undue files on the host
    (bsc#996441)

  - CVE-2016-6836: VMWARE VMXNET3 NIC device support was
    leaging information leakage. A privileged user inside
    guest could have used this to leak host memory bytes to
    a guest (bsc#994760)

  - CVE-2016-7155: In the VMWARE PVSCSI paravirtual SCSI bus
    a OOB access and/or infinite loop issue could have
    allowed a privileged user inside guest to crash the Qemu
    process resulting in DoS (bsc#997858)

  - CVE-2016-7156: In the VMWARE PVSCSI paravirtual SCSI bus
    a infinite loop issue could have allowed a privileged
    user inside guest to crash the Qemu process resulting in
    DoS (bsc#997859)

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1000048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=967012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=967013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=982017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=982018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=982019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=982222"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=982223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=982285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=982959"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=983961"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=983982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=991080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=991466"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=994760"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=994771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=994774"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=996441"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=997858"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=997859"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2391/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2392/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4453/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4454/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5105/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5106/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5107/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5126/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5238/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5337/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5338/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5403/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6490/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6833/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6836/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6888/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7116/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7155/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7156/"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162589-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b25c1b45"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12-SP1:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2016-1523=1

SUSE Linux Enterprise Desktop 12-SP1:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP1-2016-1523=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-guest-agent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-s390-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-x86");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/26");
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

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"qemu-block-rbd-2.3.1-21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"qemu-block-rbd-debuginfo-2.3.1-21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"qemu-x86-2.3.1-21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"s390x", reference:"qemu-s390-2.3.1-21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"s390x", reference:"qemu-s390-debuginfo-2.3.1-21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-2.3.1-21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-block-curl-2.3.1-21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-block-curl-debuginfo-2.3.1-21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-debugsource-2.3.1-21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-guest-agent-2.3.1-21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-guest-agent-debuginfo-2.3.1-21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-lang-2.3.1-21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-tools-2.3.1-21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-tools-debuginfo-2.3.1-21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-kvm-2.3.1-21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"qemu-2.3.1-21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"qemu-block-curl-2.3.1-21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"qemu-block-curl-debuginfo-2.3.1-21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"qemu-debugsource-2.3.1-21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"qemu-kvm-2.3.1-21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"qemu-tools-2.3.1-21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"qemu-tools-debuginfo-2.3.1-21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"qemu-x86-2.3.1-21.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu");
}
