#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:2015-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(138992);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2020-10761", "CVE-2020-13361", "CVE-2020-13362", "CVE-2020-13659", "CVE-2020-13800");
  script_xref(name:"IAVB", value:"2020-B-0041-S");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : qemu (SUSE-SU-2020:2015-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for qemu to version 4.2.1 fixes the following issues :

CVE-2020-10761: Fixed a denial of service in Network Block Device
(nbd) support infrastructure (bsc#1172710).

CVE-2020-13800: Fixed a denial of service possibility in ati-vga
emulation (bsc#1172495).

CVE-2020-13659: Fixed a NULL pointer dereference possibility in
MegaRAID SAS 8708EM2 emulation (bsc#1172386).

CVE-2020-13362: Fixed an OOB access possibility in MegaRAID SAS
8708EM2 emulation (bsc#1172383).

CVE-2020-13361: Fixed an OOB access possibility in ES1370 audio device
emulation (bsc#1172384).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1172383"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1172384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1172386"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1172495"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1172710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-10761/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-13361/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-13362/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-13659/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-13800/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20202015-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?16a75c90"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Server Applications 15-SP2 :

zypper in -t patch
SUSE-SLE-Module-Server-Applications-15-SP2-2020-2015=1

SUSE Linux Enterprise Module for Basesystem 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP2-2020-2015=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13361");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-audio-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-audio-alsa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-audio-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-audio-pa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-iscsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-ssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-guest-agent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-s390-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-ui-curses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-ui-curses-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-ui-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-ui-gtk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-ui-spice-app");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-ui-spice-app-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-x86-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP2", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"qemu-audio-alsa-4.2.1-11.4.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"qemu-audio-alsa-debuginfo-4.2.1-11.4.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"qemu-audio-pa-4.2.1-11.4.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"qemu-audio-pa-debuginfo-4.2.1-11.4.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"qemu-ui-curses-4.2.1-11.4.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"qemu-ui-curses-debuginfo-4.2.1-11.4.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"qemu-ui-gtk-4.2.1-11.4.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"qemu-ui-gtk-debuginfo-4.2.1-11.4.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"qemu-x86-4.2.1-11.4.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"qemu-x86-debuginfo-4.2.1-11.4.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"s390x", reference:"qemu-s390-4.2.1-11.4.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"s390x", reference:"qemu-s390-debuginfo-4.2.1-11.4.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-4.2.1-11.4.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-block-curl-4.2.1-11.4.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-block-curl-debuginfo-4.2.1-11.4.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-block-iscsi-4.2.1-11.4.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-block-iscsi-debuginfo-4.2.1-11.4.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-block-rbd-4.2.1-11.4.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-block-rbd-debuginfo-4.2.1-11.4.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-block-ssh-4.2.1-11.4.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-block-ssh-debuginfo-4.2.1-11.4.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-debuginfo-4.2.1-11.4.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-debugsource-4.2.1-11.4.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-guest-agent-4.2.1-11.4.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-guest-agent-debuginfo-4.2.1-11.4.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-kvm-4.2.1-11.4.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-lang-4.2.1-11.4.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-tools-4.2.1-11.4.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-tools-debuginfo-4.2.1-11.4.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-ui-spice-app-4.2.1-11.4.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-ui-spice-app-debuginfo-4.2.1-11.4.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"qemu-debuginfo-4.2.1-11.4.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"qemu-debugsource-4.2.1-11.4.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"qemu-tools-4.2.1-11.4.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"qemu-tools-debuginfo-4.2.1-11.4.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu");
}
