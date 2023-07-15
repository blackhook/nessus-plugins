#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-868.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(150754);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/16");

  script_cve_id("CVE-2021-3514");

  script_name(english:"openSUSE Security Update : 389-ds (openSUSE-2021-868)");
  script_summary(english:"Check for the openSUSE-2021-868 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for 389-ds fixes the following issues :

  - CVE-2021-3514: Fixed a sync_repl NULL pointer
    dereference in sync_create_state_control() (bsc#1185356)

389-ds was updated to version 1.4.3.23~git0.f53d0132b :

Bump version to 1.4.3.23 :

  - Issue 4725 - [RFE] DS - Update the password policy to
    support a Temporary Password Rules (#4727)

  - Issue 4759 - Fix coverity issue (#4760)

  - Issue 4656 - Fix cherry pick error around replication
    enabling

  - Issue 4701 - RFE - Exclude attributes from retro
    changelog (#4723) (#4746)

  - Issue 4742 - UI - should always use LDAPI path when
    calling CLI

  - Issue 4667 - incorrect accounting of readers in vattr
    rwlock (#4732)

  - Issue 4711 - SIGSEV with sync_repl (#4738)

  - Issue 4649 - fix testcase importing ContentSyncPlugin

  - Issue 2736 - Warnings from automatic shebang munging
    macro

  - Issue 2736 -
    https://github.com/389ds/389-ds-base/issues/2736

  - Issue 4706 - negative wtime in access log for CMP
    operations

Bump version to 1.4.3.22 :

  - Issue 4671 - UI - Fix browser crashes

  - lib389 - Add ContentSyncPlugin class

  - Issue 4656 - lib389 - fix cherry pick error

  - Issue 4229 - Fix Rust linking

  - Issue 4658 - monitor - connection start date is
    incorrect

  - Issue 2621 - lib389 - backport
    ds_supports_new_changelog()

  - Issue 4656 - Make replication CLI backwards compatible
    with role name change

  - Issue 4656 - Remove problematic language from
    UI/CLI/lib389

  - Issue 4459 - lib389 - Default paths should use dse.ldif
    if the server is down

  - Issue 4663 - CLI - unable to add objectclass/attribute
    without x-origin

Bump version to 1.4.3.21 :

  - Issue 4169 - UI - updates on the tuning page are not
    reflected in the UI

  - Issue 4588 - BUG - unable to compile without xcrypt
    (#4589)

  - Issue 4513 - Fix replication CI test failures (#4557)

  - Issue 4646 - CLI/UI - revise DNA plugin management

  - Issue 4644 - Large updates can reset the CLcache to the
    beginning of the changelog (#4647)

  - Issue 4649 - crash in sync_repl when a MODRDN create a
    cenotaph (#4652)

  - Issue 4615 - log message when psearch first exceeds max
    threads per conn

Bump version to 1.4.3.20 :

  - Issue 4324 - Some architectures the cache line size file
    does not exist

  - Issue 4593 - RFE - Print help when nsSSLPersonalitySSL
    is not found (#4614)

This update was imported from the SUSE:SLE-15-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185356"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/389ds/389-ds-base/issues/2736"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected 389-ds packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:389-ds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:389-ds-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:389-ds-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:389-ds-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:389-ds-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:389-ds-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lib389");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsvrcore0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsvrcore0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"389-ds-1.4.3.23~git0.f53d0132b-lp152.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"389-ds-debuginfo-1.4.3.23~git0.f53d0132b-lp152.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"389-ds-debugsource-1.4.3.23~git0.f53d0132b-lp152.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"389-ds-devel-1.4.3.23~git0.f53d0132b-lp152.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"389-ds-snmp-1.4.3.23~git0.f53d0132b-lp152.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"389-ds-snmp-debuginfo-1.4.3.23~git0.f53d0132b-lp152.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"lib389-1.4.3.23~git0.f53d0132b-lp152.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libsvrcore0-1.4.3.23~git0.f53d0132b-lp152.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libsvrcore0-debuginfo-1.4.3.23~git0.f53d0132b-lp152.2.15.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "389-ds / 389-ds-debuginfo / 389-ds-debugsource / 389-ds-devel / etc");
}
