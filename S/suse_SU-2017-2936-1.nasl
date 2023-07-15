#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:2936-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104429);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2017-10664", "CVE-2017-10806", "CVE-2017-10911", "CVE-2017-11334", "CVE-2017-11434", "CVE-2017-12809", "CVE-2017-13672", "CVE-2017-14167", "CVE-2017-15038", "CVE-2017-15268", "CVE-2017-15289", "CVE-2017-9524");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : qemu (SUSE-SU-2017:2936-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for qemu fixes several issues. These security issues were
fixed :

  - CVE-2017-15268: Qemu allowed remote attackers to cause a
    memory leak by triggering slow data-channel read
    operations, related to io/channel-websock.c
    (bsc#1062942).

  - CVE-2017-9524: The qemu-nbd server when built with the
    Network Block Device (NBD) Server support allowed remote
    attackers to cause a denial of service (segmentation
    fault and server crash) by leveraging failure to ensure
    that all initialization occurs talking to a client in
    the nbd_negotiate function (bsc#1043808).

  - CVE-2017-15289: The mode4and5 write functions allowed
    local OS guest privileged users to cause a denial of
    service (out-of-bounds write access and Qemu process
    crash) via vectors related to dst calculation
    (bsc#1063122)

  - CVE-2017-15038: Race condition in the v9fs_xattrwalk
    function local guest OS users to obtain sensitive
    information from host heap memory via vectors related to
    reading extended attributes (bsc#1062069)

  - CVE-2017-10911: The make_response function in the Linux
    kernel allowed guest OS users to obtain sensitive
    information from host OS (or other guest OS) kernel
    memory by leveraging the copying of uninitialized
    padding fields in Xen block-interface response
    structures (bsc#1057378)

  - CVE-2017-12809: The IDE disk and CD/DVD-ROM Emulator
    support allowed local guest OS privileged users to cause
    a denial of service (NULL pointer dereference and QEMU
    process crash) by flushing an empty CDROM device drive
    (bsc#1054724)

  - CVE-2017-10664: qemu-nbd did not ignore SIGPIPE, which
    allowed remote attackers to cause a denial of service
    (daemon crash) by disconnecting during a
    server-to-client reply attempt (bsc#1046636)

  - CVE-2017-10806: Stack-based buffer overflow allowed
    local guest OS users to cause a denial of service (QEMU
    process crash) via vectors related to logging debug
    messages (bsc#1047674)

  - CVE-2017-14167: Integer overflow in the load_multiboot
    function allowed local guest OS users to execute
    arbitrary code on the host via crafted multiboot header
    address values, which trigger an out-of-bounds write
    (bsc#1057585)

  - CVE-2017-11434: The dhcp_decode function in
    slirp/bootp.c allowed local guest OS users to cause a
    denial of service (out-of-bounds read) via a crafted
    DHCP options string (bsc#1049381)

  - CVE-2017-11334: The address_space_write_continue
    function allowed local guest OS privileged users to
    cause a denial of service (out-of-bounds access and
    guest instance crash) by leveraging use of
    qemu_map_ram_ptr to access guest ram block area
    (bsc#1048902)

  - CVE-2017-13672: The VGA display emulator support allowed
    local guest OS privileged users to cause a denial of
    service (out-of-bounds read and QEMU process crash) via
    vectors involving display update (bsc#1056334)

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1043176"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1043808"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1046636"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1047674"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1048902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1054724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1056334"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1057378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1057585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1057966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1059369"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1062069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1062942"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1063122"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=997358"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10664/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10806/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10911/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11334/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11434/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12809/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-13672/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14167/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15038/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15268/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15289/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9524/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20172936-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6562e001"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2017-1821=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2017-1821=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2017-1821=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-s390-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-x86");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"qemu-block-rbd-2.6.2-41.22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"qemu-block-rbd-debuginfo-2.6.2-41.22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"qemu-x86-2.6.2-41.22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"s390x", reference:"qemu-s390-2.6.2-41.22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"s390x", reference:"qemu-s390-debuginfo-2.6.2-41.22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"qemu-2.6.2-41.22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"qemu-block-curl-2.6.2-41.22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"qemu-block-curl-debuginfo-2.6.2-41.22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"qemu-block-ssh-2.6.2-41.22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"qemu-block-ssh-debuginfo-2.6.2-41.22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"qemu-debugsource-2.6.2-41.22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"qemu-guest-agent-2.6.2-41.22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"qemu-guest-agent-debuginfo-2.6.2-41.22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"qemu-lang-2.6.2-41.22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"qemu-tools-2.6.2-41.22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"qemu-tools-debuginfo-2.6.2-41.22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"qemu-kvm-2.6.2-41.22.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"qemu-2.6.2-41.22.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"qemu-block-curl-2.6.2-41.22.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"qemu-block-curl-debuginfo-2.6.2-41.22.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"qemu-debugsource-2.6.2-41.22.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"qemu-kvm-2.6.2-41.22.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"qemu-tools-2.6.2-41.22.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"qemu-tools-debuginfo-2.6.2-41.22.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"qemu-x86-2.6.2-41.22.2")) flag++;


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
