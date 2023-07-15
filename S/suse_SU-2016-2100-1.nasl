#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2100-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(93298);
  script_version("2.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-3672", "CVE-2016-3158", "CVE-2016-3159", "CVE-2016-3710", "CVE-2016-3960", "CVE-2016-4001", "CVE-2016-4002", "CVE-2016-4020", "CVE-2016-4037", "CVE-2016-4439", "CVE-2016-4441", "CVE-2016-4453", "CVE-2016-4454", "CVE-2016-4952", "CVE-2016-4962", "CVE-2016-4963", "CVE-2016-5105", "CVE-2016-5106", "CVE-2016-5107", "CVE-2016-5126", "CVE-2016-5238", "CVE-2016-5337", "CVE-2016-5338", "CVE-2016-5403", "CVE-2016-6258", "CVE-2016-6351");
  script_xref(name:"IAVB", value:"2016-B-0118-S");

  script_name(english:"SUSE SLES11 Security Update : xen (SUSE-SU-2016:2100-1) (Bunker Buster)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for xen fixes the several issues. These security issues
were fixed :

  - CVE-2014-3672: The qemu implementation in libvirt Xen
    allowed local guest OS users to cause a denial of
    service (host disk consumption) by writing to stdout or
    stderr (bsc#981264).

  - CVE-2016-3158: The xrstor function did not properly
    handle writes to the hardware FSW.ES bit when running on
    AMD64 processors, which allowed local guest OS users to
    obtain sensitive register content information from
    another guest by leveraging pending exception and mask
    bits (bsc#973188).

  - CVE-2016-3159: The fpu_fxrstor function in
    arch/x86/i387.c did not properly handle writes to the
    hardware FSW.ES bit when running on AMD64 processors,
    which allowed local guest OS users to obtain sensitive
    register content information from another guest by
    leveraging pending exception and mask bits (bsc#973188).

  - CVE-2016-3710: The VGA module improperly performed
    bounds checking on banked access to video memory, which
    allowed local guest OS administrators to execute
    arbitrary code on the host by changing access modes
    after setting the bank register, aka the 'Dark Portal'
    issue (bsc#978164).

  - CVE-2016-3960: Integer overflow in the x86 shadow
    pagetable code allowed local guest OS users to cause a
    denial of service (host crash) or possibly gain
    privileges by shadowing a superpage mapping
    (bsc#974038).

  - CVE-2016-4001: Buffer overflow in the
    stellaris_enet_receive function, when the Stellaris
    ethernet controller is configured to accept large
    packets, allowed remote attackers to cause a denial of
    service (QEMU crash) via a large packet (bsc#975130).

  - CVE-2016-4002: Buffer overflow in the mipsnet_receive
    function, when the guest NIC is configured to accept
    large packets, allowed remote attackers to cause a
    denial of service (memory corruption and QEMU crash) or
    possibly execute arbitrary code via a packet larger than
    1514 bytes (bsc#975138).

  - CVE-2016-4020: The patch_instruction function did not
    initialize the imm32 variable, which allowed local guest
    OS administrators to obtain sensitive information from
    host stack memory by accessing the Task Priority
    Register (TPR) (bsc#975907).

  - CVE-2016-4037: The ehci_advance_state function in
    hw/usb/hcd-ehci.c allowed local guest OS administrators
    to cause a denial of service (infinite loop and CPU
    consumption) via a circular split isochronous transfer
    descriptor (siTD) list (bsc#976111).

  - CVE-2016-4439: The esp_reg_write function in the 53C9X
    Fast SCSI Controller (FSC) support did not properly
    check command buffer length, which allowed local guest
    OS administrators to cause a denial of service
    (out-of-bounds write and QEMU process crash) or
    potentially execute arbitrary code on the host via
    unspecified vectors (bsc#980716).

  - CVE-2016-4441: The get_cmd function in the 53C9X Fast
    SCSI Controller (FSC) support did not properly check DMA
    length, which allowed local guest OS administrators to
    cause a denial of service (out-of-bounds write and QEMU
    process crash) via unspecified vectors, involving an
    SCSI command (bsc#980724).

  - CVE-2016-4453: The vmsvga_fifo_run function allowed
    local guest OS administrators to cause a denial of
    service (infinite loop and QEMU process crash) via a VGA
    command (bsc#982225).

  - CVE-2016-4454: The vmsvga_fifo_read_raw function allowed
    local guest OS administrators to obtain sensitive host
    memory information or cause a denial of service (QEMU
    process crash) by changing FIFO registers and issuing a
    VGA command, which triggered an out-of-bounds read
    (bsc#982224).

  - CVE-2016-4952: Out-of-bounds access issue in
    pvsci_ring_init_msg/data routines (bsc#981276).

  - CVE-2016-4962: The libxl device-handling allowed local
    OS guest administrators to cause a denial of service
    (resource consumption or management facility confusion)
    or gain host OS privileges by manipulating information
    in guest controlled areas of xenstore (bsc#979620).

  - CVE-2016-4963: The libxl device-handling allowed local
    guest OS users with access to the driver domain to cause
    a denial of service (management tool confusion) by
    manipulating information in the backend directories in
    xenstore (bsc#979670).

  - CVE-2016-5105: Stack information leakage while reading
    configuration (bsc#982024).

  - CVE-2016-5106: Out-of-bounds write while setting
    controller properties (bsc#982025).

  - CVE-2016-5107: Out-of-bounds read in
    megasas_lookup_frame() function (bsc#982026).

  - CVE-2016-5126: Heap-based buffer overflow in the
    iscsi_aio_ioctl function allowed local guest OS users to
    cause a denial of service (QEMU process crash) or
    possibly execute arbitrary code via a crafted iSCSI
    asynchronous I/O ioctl call (bsc#982286).

  - CVE-2016-5238: The get_cmd function in hw/scsi/esp.c
    might have allowed local guest OS administrators to
    cause a denial of service (out-of-bounds write and QEMU
    process crash) via vectors related to reading from the
    information transfer buffer in non-DMA mode
    (bsc#982960).

  - CVE-2016-5337: The megasas_ctrl_get_info function
    allowed local guest OS administrators to obtain
    sensitive host memory information via vectors related to
    reading device control information (bsc#983973).

  - CVE-2016-5338: The (1) esp_reg_read and (2)
    esp_reg_write functions allowed local guest OS
    administrators to cause a denial of service (QEMU
    process crash) or execute arbitrary code on the host via
    vectors related to the information transfer buffer
    (bsc#983984).

  - CVE-2016-6258: Potential privilege escalation in PV
    guests (XSA-182) (bsc#988675).

  - bsc#978295: x86 software guest page walk PS bit handling
    flaw (XSA-176)

  - CVE-2016-5403: virtio: unbounded memory allocation on
    host via guest leading to DoS (XSA-184) (bsc#990923)

  - CVE-2016-6351: scsi: esp: OOB write access in esp_do_dma
    (bsc#990843)

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=954872"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=955399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=957986"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=958848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=961600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=963161"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=964427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=967630"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=973188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=974038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=974912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=975130"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=975138"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=975907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=976058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=976111"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=978164"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=978295"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=978413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=979035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=979620"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=979670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=980716"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=980724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=981264"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=981276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=982024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=982025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=982026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=982224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=982225"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=982286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=982695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=982960"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=983973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=983984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=985503"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=986586"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=988675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=989235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=990843"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=990923"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3672/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3158/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3159/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3710/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3960/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4001/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4002/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4020/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4037/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4439/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4441/"
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
    value:"https://www.suse.com/security/cve/CVE-2016-4952/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4962/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4963/"
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
    value:"https://www.suse.com/security/cve/CVE-2016-6258/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6351/"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162100-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e36eb852"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-xen-12702=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-xen-12702=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-xen-12702=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/02");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"xen-kmp-default-4.4.4_07_3.0.101_77-37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"xen-libs-4.4.4_07-37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"xen-tools-domU-4.4.4_07-37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"xen-4.4.4_07-37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"xen-doc-html-4.4.4_07-37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"xen-libs-32bit-4.4.4_07-37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"xen-tools-4.4.4_07-37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"xen-kmp-pae-4.4.4_07_3.0.101_77-37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"xen-kmp-default-4.4.4_07_3.0.101_77-37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"xen-libs-4.4.4_07-37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"xen-tools-domU-4.4.4_07-37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"xen-kmp-pae-4.4.4_07_3.0.101_77-37.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen");
}
