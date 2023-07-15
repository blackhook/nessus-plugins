#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2021.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(128409);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2018-10892",
    "CVE-2019-13509",
    "CVE-2019-14271",
    "CVE-2019-5736"
  );
  script_xref(name:"CEA-ID", value:"CEA-2019-0725");

  script_name(english:"openSUSE Security Update : containerd / docker / docker-runc / etc (openSUSE-2019-2021)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for containerd, docker, docker-runc,
golang-github-docker-libnetwork fixes the following issues :

Docker :

  - CVE-2019-14271: Fixed a code injection if the nsswitch
    facility dynamically loaded a library inside a chroot
    (bsc#1143409).

  - CVE-2019-13509: Fixed an information leak in the debug
    log (bsc#1142160).

  - Update to version 19.03.1-ce, see changelog at
    /usr/share/doc/packages/docker/CHANGELOG.md
    (bsc#1142413, bsc#1139649).

runc :

  - Use %config(noreplace) for /etc/docker/daemon.json
    (bsc#1138920).

  - Update to runc 425e105d5a03, which is required by Docker
    (bsc#1139649).

containerd :

  - CVE-2019-5736: Fixed a container breakout vulnerability
    (bsc#1121967).

  - Update to containerd v1.2.6, which is required by docker
    (bsc#1139649).

golang-github-docker-libnetwork :

  - Update to version
    git.fc5a7d91d54cc98f64fc28f9e288b46a0bee756c, which is
    required by docker (bsc#1142413, bsc#1139649).

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100331");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121967");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138920");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1139649");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142160");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1143409");
  script_set_attribute(attribute:"solution", value:
"Update the affected containerd / docker / docker-runc / etc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5736");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Docker Container Escape Via runC Overwrite');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:containerd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:containerd-ctr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-libnetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-libnetwork-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-runc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:golang-github-docker-libnetwork");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ( rpm_check(release:"SUSE15.1", reference:"containerd-1.2.6-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"containerd-ctr-1.2.6-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"docker-19.03.1_ce-lp151.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"docker-bash-completion-19.03.1_ce-lp151.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"docker-debuginfo-19.03.1_ce-lp151.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"docker-libnetwork-0.7.0.1+gitr2800_fc5a7d91d54c-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"docker-libnetwork-debuginfo-0.7.0.1+gitr2800_fc5a7d91d54c-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"docker-runc-1.0.0rc8+gitr3826_425e105d5a03-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"docker-runc-debuginfo-1.0.0rc8+gitr3826_425e105d5a03-lp151.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"docker-test-19.03.1_ce-lp151.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"docker-test-debuginfo-19.03.1_ce-lp151.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"docker-zsh-completion-19.03.1_ce-lp151.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"golang-github-docker-libnetwork-0.7.0.1+gitr2800_fc5a7d91d54c-lp151.2.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "containerd / containerd-ctr / docker-runc / docker-runc-debuginfo / etc");
}
