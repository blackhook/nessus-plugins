#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:3912-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(119215);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2018-10839", "CVE-2018-15746", "CVE-2018-17958", "CVE-2018-17962", "CVE-2018-17963", "CVE-2018-18849");

  script_name(english:"SUSE SLES12 Security Update : qemu (SUSE-SU-2018:3912-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for qemu fixes the following issues :

Security issues fixed :

CVE-2018-10839: Fixed NE2000 NIC emulation support that is vulnerable
to an integer overflow, which could lead to buffer overflow issue. It
could occur when receiving packets over the network. A user inside
guest could use this flaw to crash the Qemu process resulting in DoS
(bsc#1110910).

CVE-2018-15746: Fixed qemu-seccomp.c that might allow local OS guest
users to cause a denial of service (guest crash) by leveraging
mishandling of the seccomp policy for threads other than the main
thread (bsc#1106222).

CVE-2018-17958: Fixed a Buffer Overflow in rtl8139_do_receive in
hw/net/rtl8139.c because an incorrect integer data type is used
(bsc#1111006).

CVE-2018-17962: Fixed a Buffer Overflow in pcnet_receive in
hw/net/pcnet.c because an incorrect integer data type is used
(bsc#1111010).

CVE-2018-17963: Fixed qemu_deliver_packet_iov in net/net.c that
accepts packet sizes greater than INT_MAX, which allows attackers to
cause a denial of service or possibly have unspecified other impact.
(bsc#1111013)

CVE-2018-18849: Fixed an out of bounds memory access issue that was
found in the LSI53C895A SCSI Host Bus Adapter emulation while writing
a message in lsi_do_msgin. It could occur during migration if the
'msg_len' field has an invalid value. A user/process could use this
flaw to crash the Qemu process resulting in DoS (bsc#1114422).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1106222"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1110910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1111006"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1111010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1111013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1114422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-10839/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-15746/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-17958/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-17962/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-17963/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-18849/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20183912-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?691b947d"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2018-2781=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-x86-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"qemu-block-rbd-2.0.2-48.46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"qemu-block-rbd-debuginfo-2.0.2-48.46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"qemu-x86-2.0.2-48.46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"qemu-x86-debuginfo-2.0.2-48.46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"qemu-s390-2.0.2-48.46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"qemu-s390-debuginfo-2.0.2-48.46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"qemu-2.0.2-48.46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"qemu-block-curl-2.0.2-48.46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"qemu-block-curl-debuginfo-2.0.2-48.46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"qemu-debugsource-2.0.2-48.46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"qemu-guest-agent-2.0.2-48.46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"qemu-guest-agent-debuginfo-2.0.2-48.46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"qemu-kvm-2.0.2-48.46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"qemu-lang-2.0.2-48.46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"qemu-tools-2.0.2-48.46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"qemu-tools-debuginfo-2.0.2-48.46.2")) flag++;


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
