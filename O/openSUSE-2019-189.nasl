#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-189.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(122293);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-16873", "CVE-2018-16874", "CVE-2018-16875");

  script_name(english:"openSUSE Security Update : docker (openSUSE-2019-189)");
  script_summary(english:"Check for the openSUSE-2019-189 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for containerd, docker, docker-runc and
golang-github-docker-libnetwork fixes the following issues :

Security issues fixed for containerd, docker, docker-runc and
golang-github-docker-libnetwork :

  - CVE-2018-16873: cmd/go: remote command execution during
    'go get -u' (bsc#1118897)

  - CVE-2018-16874: cmd/go: directory traversal in 'go get'
    via curly braces in import paths (bsc#1118898)

  - CVE-2018-16875: crypto/x509: CPU denial of service
    (bsc#1118899)

Non-security issues fixed for docker :

  - Disable leap based builds for kubic flavor (bsc#1121412)

  - Allow users to explicitly specify the NIS domainname of
    a container (bsc#1001161)

  - Update docker.service to match upstream and avoid rlimit
    problems (bsc#1112980)

  - Allow docker images larger then 23GB (bsc#1118990)

  - Docker version update to version 18.09.0-ce
    (bsc#1115464)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1001161"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115464"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121412"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected docker packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16874");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:containerd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:containerd-ctr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:containerd-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-libnetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-libnetwork-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-runc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-runc-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:golang-github-docker-libnetwork");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"containerd-1.1.2-lp150.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"containerd-ctr-1.1.2-lp150.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"containerd-test-1.1.2-lp150.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"docker-18.09.0_ce-lp150.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"docker-bash-completion-18.09.0_ce-lp150.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"docker-debuginfo-18.09.0_ce-lp150.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"docker-debugsource-18.09.0_ce-lp150.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"docker-libnetwork-0.7.0.1+gitr2704_6da50d197830-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"docker-libnetwork-debuginfo-0.7.0.1+gitr2704_6da50d197830-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"docker-runc-1.0.0rc5+gitr3562_69663f0bd4b6-lp150.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"docker-runc-debuginfo-1.0.0rc5+gitr3562_69663f0bd4b6-lp150.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"docker-runc-test-1.0.0rc5+gitr3562_69663f0bd4b6-lp150.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"docker-test-18.09.0_ce-lp150.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"docker-test-debuginfo-18.09.0_ce-lp150.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"docker-zsh-completion-18.09.0_ce-lp150.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"golang-github-docker-libnetwork-0.7.0.1+gitr2704_6da50d197830-lp150.3.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "containerd / containerd-ctr / containerd-test / docker-runc / etc");
}
