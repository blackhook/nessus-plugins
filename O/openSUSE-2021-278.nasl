#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-278.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(146506);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id("CVE-2020-15257", "CVE-2021-21284", "CVE-2021-21285");

  script_name(english:"openSUSE Security Update : containerd / docker / docker-runc / etc (openSUSE-2021-278)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for containerd, docker, docker-runc,
golang-github-docker-libnetwork fixes the following issues :

Security issues fixed :

  - CVE-2020-15257: Fixed a privilege escalation in
    containerd (bsc#1178969).

  - CVE-2021-21284: potential privilege escalation when the
    root user in the remapped namespace has access to the
    host filesystem (bsc#1181732)

  - CVE-2021-21285: pulling a malformed Docker image
    manifest crashes the dockerd daemon (bsc#1181730)

Non-security issues fixed :

  - Update Docker to 19.03.15-ce. See upstream changelog in
    the packaged
    /usr/share/doc/packages/docker/CHANGELOG.md. This update
    includes fixes for bsc#1181732 (CVE-2021-21284) and
    bsc#1181730 (CVE-2021-21285).

  - Only apply the boo#1178801 libnetwork patch to handle
    firewalld on openSUSE. It appears that SLES doesn't like
    the patch. (bsc#1180401)

  - Update to containerd v1.3.9, which is needed for Docker
    v19.03.14-ce and fixes CVE-2020-15257. bsc#1180243

  - Update to containerd v1.3.7, which is required for
    Docker 19.03.13-ce. bsc#1176708

  - Update to Docker 19.03.14-ce. See upstream changelog in
    the packaged
    /usr/share/doc/packages/docker/CHANGELOG.md.
    CVE-2020-15257 bsc#1180243
    https://github.com/docker/docker-ce/releases/tag/v19.03.
    14

  - Enable fish-completion

  - Add a patch which makes Docker compatible with firewalld
    with nftables backend. Backport of
    https://github.com/moby/libnetwork/pull/2548
    (bsc#1178801, SLE-16460)

  - Update to Docker 19.03.13-ce. See upstream changelog in
    the packaged
    /usr/share/doc/packages/docker/CHANGELOG.md. bsc#1176708

  - Fixes for %_libexecdir changing to /usr/libexec
    (bsc#1174075)

  - Emergency fix: %requires_eq does not work with provide
    symbols, only effective package names. Convert back to
    regular Requires.

  - Update to Docker 19.03.12-ce. See upstream changelog in
    the packaged
    /usr/share/doc/packages/docker/CHANGELOG.md.

  - Use Go 1.13 instead of Go 1.14 because Go 1.14 can cause
    all sorts of spurrious errors due to Go returning -EINTR
    from I/O syscalls much more often (due to Go 1.14's
    pre-emptive goroutine support).

  - Add BuildRequires for all -git dependencies so that we
    catch missing dependencies much more quickly.

  - Update to libnetwork 55e924b8a842, which is required for
    Docker 19.03.14-ce. bsc#1180243

  - Add patch which makes libnetwork compatible with
    firewalld with nftables backend. Backport of
    https://github.com/moby/libnetwork/pull/2548
    (bsc#1178801, SLE-16460)

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174075");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176708");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178801");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180243");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180401");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181730");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181732");
  script_set_attribute(attribute:"see_also", value:"https://github.com/docker/docker-ce/releases/tag/v19.03.14");
  script_set_attribute(attribute:"see_also", value:"https://github.com/moby/libnetwork/pull/2548");
  script_set_attribute(attribute:"solution", value:
"Update the affected containerd / docker / docker-runc / etc packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15257");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-21284");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:containerd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:containerd-ctr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-fish-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-libnetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-libnetwork-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-runc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fish-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fish-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fish-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:golang-github-docker-libnetwork");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ( rpm_check(release:"SUSE15.2", reference:"containerd-1.3.9-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"containerd-ctr-1.3.9-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"docker-19.03.15_ce-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"docker-bash-completion-19.03.15_ce-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"docker-debuginfo-19.03.15_ce-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"docker-fish-completion-19.03.15_ce-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"docker-libnetwork-0.7.0.1+gitr2908_55e924b8a842-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"docker-libnetwork-debuginfo-0.7.0.1+gitr2908_55e924b8a842-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"docker-runc-1.0.0rc10+gitr3981_dc9208a3303f-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"docker-runc-debuginfo-1.0.0rc10+gitr3981_dc9208a3303f-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"docker-test-19.03.15_ce-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"docker-test-debuginfo-19.03.15_ce-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"docker-zsh-completion-19.03.15_ce-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"fish-2.7.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"fish-debuginfo-2.7.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"fish-debugsource-2.7.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"fish-devel-2.7.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"golang-github-docker-libnetwork-0.7.0.1+gitr2908_55e924b8a842-lp152.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "containerd / containerd-ctr / docker-runc / docker-runc-debuginfo / etc");
}
