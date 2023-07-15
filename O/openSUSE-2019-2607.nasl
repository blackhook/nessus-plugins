#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2607.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(131720);
  script_version("1.1");
  script_cvs_date("Date: 2019/12/05");

  script_name(english:"openSUSE Security Update : openafs (openSUSE-2019-2607)");
  script_summary(english:"Check for the openSUSE-2019-2607 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for openafs fixes the following issues :

Update to security-release 1.8.5, adresses :

  - OPENAFS-SA-2019-001: Skip server OUT args on error 

  - OPENAFS-SA-2019-002: Zero all server RPC args

  - OPENAFS-SA-2019-003: ubik: Avoid unlocked
    ubik_currentTrans deref

update to official version 1.8.4 

  - support Linux-kernel 5.3

  - Avoid non-dir ENOENT errors in afs_lookup

  - fix parsing of fileservers with -vlruthresh, etc.

  - other bugfixes 

update to pre-release 1.8.4pre2

  - fix builds for Linux-kernels 5.3

update to 1.8.3

  - fix broken directory layout

  - allow crypt to be set/unset on startup of client

update to pre-release 1.8.3pre1

  - fix builds for Linux-kernels 4.20 and 5.0 

  - other fixes, see RELNOTES-1.8.3pre1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openafs packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-authlibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-authlibs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-authlibs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-fuse_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-fuse_client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"openafs-1.8.5-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"openafs-authlibs-1.8.5-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"openafs-authlibs-debuginfo-1.8.5-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"openafs-authlibs-devel-1.8.5-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"openafs-client-1.8.5-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"openafs-client-debuginfo-1.8.5-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"openafs-debuginfo-1.8.5-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"openafs-debugsource-1.8.5-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"openafs-devel-1.8.5-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"openafs-devel-debuginfo-1.8.5-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"openafs-fuse_client-1.8.5-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"openafs-fuse_client-debuginfo-1.8.5-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"openafs-kernel-source-1.8.5-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"openafs-kmp-default-1.8.5_k4.12.14_lp151.28.32-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"openafs-kmp-default-debuginfo-1.8.5_k4.12.14_lp151.28.32-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"openafs-server-1.8.5-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"openafs-server-debuginfo-1.8.5-lp151.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openafs / openafs-authlibs / openafs-authlibs-debuginfo / etc");
}
