#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1569.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119759);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-15750", "CVE-2018-15751");

  script_name(english:"openSUSE Security Update : salt (openSUSE-2018-1569)");
  script_summary(english:"Check for the openSUSE-2018-1569 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for salt fixes the following issues :

Security issues fixed :

  - CVE-2018-15750: Fixed directory traversal vulnerability
    in salt-api (bsc#1113698).

  - CVE-2018-15751: Fixed remote authentication bypass in
    salt-api(netapi) that allows to execute arbitrary
    commands (bsc#1113699).

Non-security issues fixed :

  - Improved handling of LDAP group id. gid is no longer
    treated as a string, which could have lead to faulty
    group creations (bsc#1113784).

  - Fixed async call to process manager (bsc#1110938)

  - Fixed OS arch detection when RPM is not installed
    (bsc#1114197)

  - Crontab module fix: file attributes option missing
    (bsc#1114824)

  - Fix git_pillar merging across multiple __env__
    repositories (bsc#1112874)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110938"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112874"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113699"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114197"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114824"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected salt packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-cloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-fish-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-master");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-minion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-syndic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"python2-salt-2018.3.0-lp150.3.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-salt-2018.3.0-lp150.3.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"salt-2018.3.0-lp150.3.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"salt-api-2018.3.0-lp150.3.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"salt-bash-completion-2018.3.0-lp150.3.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"salt-cloud-2018.3.0-lp150.3.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"salt-fish-completion-2018.3.0-lp150.3.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"salt-master-2018.3.0-lp150.3.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"salt-minion-2018.3.0-lp150.3.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"salt-proxy-2018.3.0-lp150.3.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"salt-ssh-2018.3.0-lp150.3.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"salt-syndic-2018.3.0-lp150.3.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"salt-zsh-completion-2018.3.0-lp150.3.17.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python2-salt / python3-salt / salt / salt-api / etc");
}
