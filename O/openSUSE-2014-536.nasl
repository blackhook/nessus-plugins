#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-536.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77659);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-0475", "CVE-2014-5119", "CVE-2014-6040");
  script_bugtraq_id(68505, 68983, 69472);

  script_name(english:"openSUSE Security Update : glibc (openSUSE-SU-2014:1115-1)");
  script_summary(english:"Check for the openSUSE-2014-536 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"glibc was updated to fix three security issues :

  - A directory traversal in locale environment handling was
    fixed (CVE-2014-0475, bnc#887022, GLIBC BZ #17137)

  - Disable gconv transliteration module loading which could
    be used for code execution (CVE-2014-5119, bnc#892073,
    GLIBC BZ #17187)

  - Fix crashes on invalid input in IBM gconv modules
    (CVE-2014-6040, bnc#894553, BZ #17325)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=887022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=892073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=894553"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2014-09/msg00017.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glibc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-static-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-i18ndata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-obsolete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-obsolete-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-profile-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nscd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nscd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/12");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"glibc-2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-debuginfo-2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-debugsource-2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-devel-2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-devel-debuginfo-2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-devel-static-2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-extra-2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-extra-debuginfo-2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-html-2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-i18ndata-2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-info-2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-locale-2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-locale-debuginfo-2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-obsolete-2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-obsolete-debuginfo-2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-profile-2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-utils-2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-utils-debuginfo-2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-utils-debugsource-2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"nscd-2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"nscd-debuginfo-2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"glibc-32bit-2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"glibc-debuginfo-32bit-2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"glibc-devel-32bit-2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"glibc-devel-debuginfo-32bit-2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"glibc-devel-static-32bit-2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"glibc-locale-32bit-2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"glibc-locale-debuginfo-32bit-2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"glibc-profile-32bit-2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"glibc-utils-32bit-2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"glibc-utils-debuginfo-32bit-2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"glibc-2.18-4.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"glibc-debuginfo-2.18-4.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"glibc-debugsource-2.18-4.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"glibc-devel-2.18-4.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"glibc-devel-debuginfo-2.18-4.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"glibc-devel-static-2.18-4.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"glibc-extra-2.18-4.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"glibc-extra-debuginfo-2.18-4.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"glibc-html-2.18-4.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"glibc-i18ndata-2.18-4.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"glibc-info-2.18-4.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"glibc-locale-2.18-4.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"glibc-locale-debuginfo-2.18-4.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"glibc-obsolete-2.18-4.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"glibc-obsolete-debuginfo-2.18-4.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"glibc-profile-2.18-4.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"glibc-utils-2.18-4.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"glibc-utils-debuginfo-2.18-4.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"glibc-utils-debugsource-2.18-4.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"nscd-2.18-4.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"nscd-debuginfo-2.18-4.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"glibc-32bit-2.18-4.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"glibc-debuginfo-32bit-2.18-4.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"glibc-devel-32bit-2.18-4.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"glibc-devel-debuginfo-32bit-2.18-4.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"glibc-devel-static-32bit-2.18-4.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"glibc-locale-32bit-2.18-4.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"glibc-locale-debuginfo-32bit-2.18-4.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"glibc-profile-32bit-2.18-4.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"glibc-utils-32bit-2.18-4.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"glibc-utils-debuginfo-32bit-2.18-4.21.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc");
}
