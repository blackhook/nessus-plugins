#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1626.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119952);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-16873", "CVE-2018-16874", "CVE-2018-16875", "CVE-2018-7187");

  script_name(english:"openSUSE Security Update : containerd / docker and go (openSUSE-2018-1626)");
  script_summary(english:"Check for the openSUSE-2018-1626 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for containerd, docker and go fixes the following issues :

containerd and docker :

  - Add backport for building containerd (bsc#1102522,
    bsc#1113313)

  - Upgrade to containerd v1.1.2, which is required for
    Docker v18.06.1-ce. (bsc#1102522)

  - Enable seccomp support (fate#325877)

  - Update to containerd v1.1.1, which is the required
    version for the Docker v18.06.0-ce upgrade.
    (bsc#1102522)

  - Put containerd under the podruntime slice (bsc#1086185) 

  - 3rd party registries used the default Docker certificate
    (bsc#1084533)

  - Handle build breakage due to missing 'export GOPATH'
    (caused by resolution of boo#1119634). I believe Docker
    is one of the only packages with this problem.

go :

  - golang: arbitrary command execution via VCS path
    (bsc#1081495, CVE-2018-7187)

  - Make profile.d/go.sh no longer set GOROOT=, in order to
    make switching between versions no longer break. This
    ends up removing the need for go.sh entirely (because
    GOPATH is also set automatically) (boo#1119634)

  - Fix a regression that broke go get for import path
    patterns containing '...' (bsc#1119706)

Additionally, the package go1.10 has been added.

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047218"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074971"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1080978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1081495"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084533"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094680"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095817"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102522"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114209"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118898"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118899"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/325877"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected containerd / docker and go packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:containerd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:containerd-ctr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:containerd-kubic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:containerd-kubic-ctr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:containerd-kubic-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:containerd-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-kubic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-kubic-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-kubic-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-kubic-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-kubic-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-kubic-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-kubic-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-libnetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-libnetwork-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-libnetwork-kubic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-libnetwork-kubic-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-runc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-runc-kubic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-runc-kubic-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-runc-kubic-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-runc-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:go-race");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:go1.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:go1.10-race");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:golang-github-docker-libnetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:golang-github-docker-libnetwork-kubic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:golang-packaging");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"containerd-kubic-test-1.1.2-lp150.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"containerd-test-1.1.2-lp150.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"docker-bash-completion-18.06.1_ce-lp150.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"docker-kubic-bash-completion-18.06.1_ce-lp150.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"docker-kubic-zsh-completion-18.06.1_ce-lp150.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"docker-runc-kubic-test-1.0.0rc5+gitr3562_69663f0bd4b6-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"docker-runc-test-1.0.0rc5+gitr3562_69663f0bd4b6-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"docker-zsh-completion-18.06.1_ce-lp150.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"go-1.10.4-lp150.2.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"golang-packaging-15.0.11-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"containerd-1.1.2-lp150.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"containerd-ctr-1.1.2-lp150.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"containerd-kubic-1.1.2-lp150.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"containerd-kubic-ctr-1.1.2-lp150.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"docker-18.06.1_ce-lp150.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"docker-debuginfo-18.06.1_ce-lp150.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"docker-debugsource-18.06.1_ce-lp150.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"docker-kubic-18.06.1_ce-lp150.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"docker-kubic-debuginfo-18.06.1_ce-lp150.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"docker-kubic-debugsource-18.06.1_ce-lp150.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"docker-kubic-test-18.06.1_ce-lp150.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"docker-kubic-test-debuginfo-18.06.1_ce-lp150.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"docker-libnetwork-0.7.0.1+gitr2664_3ac297bc7fd0-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"docker-libnetwork-debuginfo-0.7.0.1+gitr2664_3ac297bc7fd0-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"docker-libnetwork-kubic-0.7.0.1+gitr2664_3ac297bc7fd0-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"docker-libnetwork-kubic-debuginfo-0.7.0.1+gitr2664_3ac297bc7fd0-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"docker-runc-1.0.0rc5+gitr3562_69663f0bd4b6-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"docker-runc-debuginfo-1.0.0rc5+gitr3562_69663f0bd4b6-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"docker-runc-kubic-1.0.0rc5+gitr3562_69663f0bd4b6-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"docker-runc-kubic-debuginfo-1.0.0rc5+gitr3562_69663f0bd4b6-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"docker-test-18.06.1_ce-lp150.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"docker-test-debuginfo-18.06.1_ce-lp150.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"go-race-1.10.4-lp150.2.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"go1.10-1.10.7-lp150.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"go1.10-race-1.10.7-lp150.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"golang-github-docker-libnetwork-0.7.0.1+gitr2664_3ac297bc7fd0-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"golang-github-docker-libnetwork-kubic-0.7.0.1+gitr2664_3ac297bc7fd0-lp150.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "containerd / containerd-ctr / containerd-test / containerd-kubic / etc");
}
