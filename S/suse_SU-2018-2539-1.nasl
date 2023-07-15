#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:2539-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(120088);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2018-10853", "CVE-2018-10902", "CVE-2018-15572", "CVE-2018-9363");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : kernel (SUSE-SU-2018:2539-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The SUSE Linux Enterprise 15 kernel was updated to receive various
security and bugfixes. The following security bugs were fixed :

  - CVE-2018-15572: The spectre_v2_select_mitigation
    function in arch/x86/kernel/cpu/bugs.c did not always
    fill RSB upon a context switch, which made it easier for
    attackers to conduct userspace-userspace spectreRSB
    attacks (bnc#1102517 bnc#1105296).

  - CVE-2018-10902: It was found that the raw midi kernel
    driver did not protect against concurrent access which
    leads to a double realloc (double free) in
    snd_rawmidi_input_params() and
    snd_rawmidi_output_status() which are part of
    snd_rawmidi_ioctl() handler in rawmidi.c file. A
    malicious local attacker could possibly use this for
    privilege escalation (bnc#1105322).

  - CVE-2018-9363: A buffer overflow in bluetooth HID report
    processing could be used by malicious bluetooth devices
    to crash the kernel or potentially execute code
    (bnc#1105292).

  - CVE-2018-10853: A KVM guest userspace to guest kernel
    write was fixed, which could be used by guest users to
    crash the guest kernel (bnc#1097104).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1046305"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1046306"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1046307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1051510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1065600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1081917"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1083647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1086288"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1086315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1086317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1086327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1086331"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1086906"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1087092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1090888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1097104"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1097577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1097583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1097584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1097585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1097586"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1097587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1097588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1097808"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1100132"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1101480"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1101669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1101822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1102517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1102715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1103269"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1103277"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1103363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1103445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1103886"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1104353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1104365"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1104427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1104482"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1104494"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1104495"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1104683"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1104708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1104777"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1104890"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1104897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1105292"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1105296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1105322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1105355"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1105378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1105396"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1105467"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1105731"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=802154"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=971975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-10853/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-10902/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-15572/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-9363/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20182539-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3a33798b"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 15:zypper in -t patch
SUSE-SLE-Product-WE-15-2018-1776=1

SUSE Linux Enterprise Module for Legacy Software 15:zypper in -t patch
SUSE-SLE-Module-Legacy-15-2018-1776=1

SUSE Linux Enterprise Module for Development Tools 15:zypper in -t
patch SUSE-SLE-Module-Development-Tools-15-2018-1776=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2018-1776=1

SUSE Linux Enterprise High Availability 15:zypper in -t patch
SUSE-SLE-Product-HA-15-2018-1776=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vanilla-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vanilla-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-zfcpdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-zfcpdump-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:lttng-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:lttng-modules-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:lttng-modules-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:lttng-modules-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"lttng-modules-2.10.0-5.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"lttng-modules-debugsource-2.10.0-5.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"lttng-modules-kmp-default-2.10.0_k4.12.14_25.16-5.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"lttng-modules-kmp-default-debuginfo-2.10.0_k4.12.14_25.16-5.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-default-man-4.12.14-25.16.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-zfcpdump-4.12.14-25.16.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-zfcpdump-debuginfo-4.12.14-25.16.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-zfcpdump-debugsource-4.12.14-25.16.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"kernel-default-4.12.14-25.16.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"kernel-default-debuginfo-4.12.14-25.16.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"kernel-default-debugsource-4.12.14-25.16.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"kernel-default-devel-4.12.14-25.16.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"kernel-default-devel-debuginfo-4.12.14-25.16.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"kernel-obs-build-4.12.14-25.16.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"kernel-obs-build-debugsource-4.12.14-25.16.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"kernel-syms-4.12.14-25.16.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"kernel-vanilla-base-4.12.14-25.16.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"kernel-vanilla-base-debuginfo-4.12.14-25.16.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"kernel-vanilla-debuginfo-4.12.14-25.16.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"kernel-vanilla-debugsource-4.12.14-25.16.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"reiserfs-kmp-default-4.12.14-25.16.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"reiserfs-kmp-default-debuginfo-4.12.14-25.16.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"lttng-modules-2.10.0-5.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"lttng-modules-debugsource-2.10.0-5.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"lttng-modules-kmp-default-2.10.0_k4.12.14_25.16-5.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"lttng-modules-kmp-default-debuginfo-2.10.0_k4.12.14_25.16-5.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"s390x", reference:"kernel-default-man-4.12.14-25.16.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"s390x", reference:"kernel-zfcpdump-4.12.14-25.16.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"s390x", reference:"kernel-zfcpdump-debuginfo-4.12.14-25.16.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"s390x", reference:"kernel-zfcpdump-debugsource-4.12.14-25.16.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"kernel-default-4.12.14-25.16.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"kernel-default-debuginfo-4.12.14-25.16.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"kernel-default-debugsource-4.12.14-25.16.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"kernel-default-devel-4.12.14-25.16.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"kernel-default-devel-debuginfo-4.12.14-25.16.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"kernel-obs-build-4.12.14-25.16.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"kernel-obs-build-debugsource-4.12.14-25.16.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"kernel-syms-4.12.14-25.16.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"kernel-vanilla-base-4.12.14-25.16.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"kernel-vanilla-base-debuginfo-4.12.14-25.16.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"kernel-vanilla-debuginfo-4.12.14-25.16.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"kernel-vanilla-debugsource-4.12.14-25.16.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
