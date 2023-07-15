#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:1377-2.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(118256);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/15");

  script_cve_id("CVE-2018-3639");

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2018:1377-2) (Spectre)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The SUSE Linux Enterprise 12 SP2 LTSS kernel was updated to receive
various security and bugfixes.

The following security bug was fixed :

CVE-2018-3639: Information leaks using 'Memory Disambiguation' feature
in modern CPUs were mitigated, aka 'Spectre Variant 4' (bnc#1087082).

A new boot commandline option was introduced,
'spec_store_bypass_disable', which can have following values :

  - auto: Kernel detects whether your CPU model contains an
    implementation of Speculative Store Bypass and picks the
    most appropriate mitigation.

  - on: disable Speculative Store Bypass

  - off: enable Speculative Store Bypass

  - prctl: Control Speculative Store Bypass per thread via
    prctl. Speculative Store Bypass is enabled for a process
    by default. The state of the control is inherited on
    fork.

  - seccomp: Same as 'prctl' above, but all seccomp threads
    will disable SSB unless they explicitly opt out.

    The default is 'seccomp', meaning programs need explicit
    opt-in into the mitigation.

    Status can be queried via the
    /sys/devices/system/cpu/vulnerabilities/spec_store_bypas
    s file, containing :

  - 'Vulnerable'

  - 'Mitigation: Speculative Store Bypass disabled'

  - 'Mitigation: Speculative Store Bypass disabled via
    prctl'

  - 'Mitigation: Speculative Store Bypass disabled via prctl
    and seccomp'

The following related and non-security bugs were fixed: cpuid: Fix
cpuid.edx.7.0 propagation to guest

ext4: Fix hole length detection in ext4_ind_map_blocks()
(bsc#1090953).

ibmvnic: Clean actual number of RX or TX pools (bsc#1092289).

kvm: Introduce nopvspin kernel parameter (bsc#1056427).

kvm: Fix nopvspin static branch init usage (bsc#1056427).

powerpc/64: Use barrier_nospec in syscall entry (bsc#1068032,
bsc#1080157).

powerpc/64s: Add barrier_nospec (bsc#1068032, bsc#1080157).

powerpc/64s: Add support for ori barrier_nospec patching (bsc#1068032,
bsc#1080157).

powerpc/64s: Enable barrier_nospec based on firmware settings
(bsc#1068032, bsc#1080157).

powerpc/64s: Enhance the information in cpu_show_meltdown()
(bsc#1068032, bsc#1075087, bsc#1091041).

powerpc/64s: Enhance the information in cpu_show_spectre_v1()
(bsc#1068032).

powerpc/64s: Fix section mismatch warnings from setup_rfi_flush()
(bsc#1068032, bsc#1075087, bsc#1091041).

powerpc/64s: Move cpu_show_meltdown() (bsc#1068032, bsc#1075087,
bsc#1091041).

powerpc/64s: Patch barrier_nospec in modules (bsc#1068032,
bsc#1080157).

powerpc/64s: Wire up cpu_show_spectre_v1() (bsc#1068032, bsc#1075087,
bsc#1091041).

powerpc/64s: Wire up cpu_show_spectre_v2() (bsc#1068032, bsc#1075087,
bsc#1091041).

powerpc/powernv: Set or clear security feature flags (bsc#1068032,
bsc#1075087, bsc#1091041).

powerpc/powernv: Use the security flags in pnv_setup_rfi_flush()
(bsc#1068032, bsc#1075087, bsc#1091041).

powerpc/pseries: Add new H_GET_CPU_CHARACTERISTICS flags (bsc#1068032,
bsc#1075087, bsc#1091041).

powerpc/pseries: Fix clearing of security feature flags (bsc#1068032,
bsc#1075087, bsc#1091041).

powerpc/pseries: Restore default security feature flags on setup
(bsc#1068032, bsc#1075087, bsc#1091041).

powerpc/pseries: Set or clear security feature flags (bsc#1068032,
bsc#1075087, bsc#1091041).

powerpc/pseries: Use the security flags in pseries_setup_rfi_flush()
(bsc#1068032, bsc#1075087, bsc#1091041).

powerpc/rfi-flush: Always enable fallback flush on pseries
(bsc#1068032, bsc#1075087, bsc#1091041).

powerpc/rfi-flush: Differentiate enabled and patched flush types
(bsc#1068032, bsc#1075087, bsc#1091041).

powerpc/rfi-flush: Make it possible to call setup_rfi_flush() again
(bsc#1068032, bsc#1075087, bsc#1091041).

powerpc: Add security feature flags for Spectre/Meltdown (bsc#1068032,
bsc#1075087, bsc#1091041).

powerpc: Move default security feature flags (bsc#1068032,
bsc#1075087, bsc#1091041).

powerpc: Use barrier_nospec in copy_from_user() (bsc#1068032,
bsc#1080157).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1056427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1068032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1075087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1080157"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1087082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1090953"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1091041"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1092289"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1093215"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1094019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3639/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20181377-2/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2c461ad3"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12-SP2-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-BCL-2018-956=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_121-92_80-default");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/22");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kernel-default-4.4.121-92.80.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kernel-default-base-4.4.121-92.80.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kernel-default-base-debuginfo-4.4.121-92.80.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kernel-default-debuginfo-4.4.121-92.80.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kernel-default-debugsource-4.4.121-92.80.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kernel-default-devel-4.4.121-92.80.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kernel-syms-4.4.121-92.80.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kgraft-patch-4_4_121-92_80-default-1-3.5.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
