#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-455.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(75019);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2012-6085");

  script_name(english:"openSUSE Security Update : gpg2 (openSUSE-SU-2013:0880-1)");
  script_summary(english:"Check for the openSUSE-2013-455 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of gpg2 fixes two security issues :

  - fix for CVE-2012-6085 (bnc#798465) added
    gpg2-CVE-2012-6085.patch

  - fix for bnc#780943 added
    gpg2-set_umask_before_open_outfile.patch"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=780943"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=798465"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2013-05/msg00041.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2013-06/msg00017.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gpg2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gpg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gpg2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gpg2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gpg2-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE12\.1|SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1 / 12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"gpg2-2.0.18-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"gpg2-debuginfo-2.0.18-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"gpg2-debugsource-2.0.18-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"gpg2-lang-2.0.18-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gpg2-2.0.19-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gpg2-debuginfo-2.0.19-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gpg2-debugsource-2.0.19-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gpg2-lang-2.0.19-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gpg2-2.0.19-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gpg2-debuginfo-2.0.19-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gpg2-debugsource-2.0.19-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gpg2-lang-2.0.19-5.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gpg2 / gpg2-debuginfo / gpg2-debugsource / gpg2-lang");
}
