#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1703-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(93170);
  script_version("2.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2015-5745", "CVE-2015-7549", "CVE-2015-8504", "CVE-2015-8558", "CVE-2015-8567", "CVE-2015-8568", "CVE-2015-8613", "CVE-2015-8619", "CVE-2015-8743", "CVE-2015-8744", "CVE-2015-8745", "CVE-2015-8817", "CVE-2015-8818", "CVE-2016-1568", "CVE-2016-1714", "CVE-2016-1922", "CVE-2016-1981", "CVE-2016-2197", "CVE-2016-2198", "CVE-2016-2538", "CVE-2016-2841", "CVE-2016-2857", "CVE-2016-2858", "CVE-2016-3710", "CVE-2016-3712", "CVE-2016-4001", "CVE-2016-4002", "CVE-2016-4020", "CVE-2016-4037", "CVE-2016-4439", "CVE-2016-4441", "CVE-2016-4952");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : qemu (SUSE-SU-2016:1703-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"qemu was updated to fix 29 security issues.

These security issues were fixed :

  - CVE-2016-4439: Avoid OOB access in 53C9X emulation
    (bsc#980711)

  - CVE-2016-4441: Avoid OOB access in 53C9X emulation
    (bsc#980723)

  - CVE-2016-4952: Avoid OOB access in Vmware PV SCSI
    emulation (bsc#981266)

  - CVE-2015-8817: Avoid OOB access in PCI dma I/O
    (bsc#969121)

  - CVE-2015-8818: Avoid OOB access in PCI dma I/O
    (bsc#969122)

  - CVE-2016-3710: Fixed VGA emulation based OOB access with
    potential for guest escape (bsc#978158)

  - CVE-2016-3712: Fixed VGa emulation based DOS and OOB
    read access exploit (bsc#978160)

  - CVE-2016-4037: Fixed USB ehci based DOS (bsc#976109)

  - CVE-2016-2538: Fixed potential OOB access in USB net
    device emulation (bsc#967969)

  - CVE-2016-2841: Fixed OOB access / hang in ne2000
    emulation (bsc#969350)

  - CVE-2016-2858: Avoid potential DOS when using QEMU
    pseudo random number generator (bsc#970036)

  - CVE-2016-2857: Fixed OOB access when processing IP
    checksums (bsc#970037)

  - CVE-2016-4001: Fixed OOB access in Stellaris enet
    emulated nic (bsc#975128)

  - CVE-2016-4002: Fixed OOB access in MIPSnet emulated
    controller (bsc#975136)

  - CVE-2016-4020: Fixed possible host data leakage to guest
    from TPR access (bsc#975700)

  - CVE-2016-2197: Prevent AHCI NULL pointer dereference
    when using FIS CLB engine (bsc#964411)

  - CVE-2015-5745: Buffer overflow in virtio-serial
    (bsc#940929).

  - CVE-2015-7549: PCI NULL pointer dereferences
    (bsc#958917).

  - CVE-2015-8504: VNC floating point exception
    (bsc#958491).

  - CVE-2015-8558: Infinite loop in ehci_advance_state
    resulting in DoS (bsc#959005).

  - CVE-2015-8567: A guest repeatedly activating a vmxnet3
    device can leak host memory (bsc#959386).

  - CVE-2015-8568: A guest repeatedly activating a vmxnet3
    device can leak host memory (bsc#959386).

  - CVE-2015-8613: Wrong sized memset in megasas command
    handler (bsc#961358).

  - CVE-2015-8619: Potential DoS for long HMP sendkey
    command argument (bsc#960334).

  - CVE-2015-8743: OOB memory access in ne2000 ioport r/w
    functions (bsc#960725).

  - CVE-2015-8744: Incorrect l2 header validation could have
    lead to a crash via assert(2) call (bsc#960835).

  - CVE-2015-8745: Reading IMR registers could have lead to
    a crash via assert(2) call (bsc#960708).

  - CVE-2016-1568: AHCI use-after-free in aio port commands
    (bsc#961332).

  - CVE-2016-1714: Potential OOB memory access in processing
    firmware configuration (bsc#961691).

  - CVE-2016-1922: NULL pointer dereference when processing
    hmp i/o command (bsc#962320).

  - CVE-2016-1981: Potential DoS (infinite loop) in e1000
    device emulation by malicious privileged user within
    guest (bsc#963782).

  - CVE-2016-2198: Malicious privileged guest user were able
    to cause DoS by writing to read-only EHCI capabilities
    registers (bsc#964413).

This non-security issue was fixed

  - bsc#886378: qemu truncates vhd images in virt-rescue

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=886378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=940929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=958491"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=958917"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=959005"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=959386"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=960334"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=960708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=960725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=960835"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=961332"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=961333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=961358"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=961556"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=961691"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=962320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=963782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=964411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=964413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=967969"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=969121"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=969122"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=969350"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=970036"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=970037"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=975128"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=975136"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=975700"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=976109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=978158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=978160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=980711"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=980723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=981266"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5745/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7549/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8504/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8558/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8567/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8568/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8613/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8619/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8743/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8744/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8745/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8817/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8818/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1568/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1714/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1922/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1981/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2197/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2198/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2538/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2841/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2857/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2858/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3710/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3712/"
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
    value:"https://www.suse.com/security/cve/CVE-2016-4952/"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161703-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0f03d2ce"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12-SP1 :

zypper in -t patch SUSE-SLE-SERVER-12-SP1-2016-1007=1

SUSE Linux Enterprise Desktop 12-SP1 :

zypper in -t patch SUSE-SLE-DESKTOP-12-SP1-2016-1007=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");
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
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"qemu-block-rbd-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"qemu-block-rbd-debuginfo-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"qemu-x86-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"s390x", reference:"qemu-s390-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"s390x", reference:"qemu-s390-debuginfo-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-block-curl-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-block-curl-debuginfo-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-debugsource-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-guest-agent-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-guest-agent-debuginfo-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-lang-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-tools-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-tools-debuginfo-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-kvm-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"qemu-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"qemu-block-curl-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"qemu-block-curl-debuginfo-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"qemu-debugsource-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"qemu-kvm-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"qemu-tools-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"qemu-tools-debuginfo-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"qemu-x86-2.3.1-14.1")) flag++;


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
