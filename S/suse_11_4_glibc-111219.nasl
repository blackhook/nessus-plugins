#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update glibc-5554.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(75853);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-5029");

  script_name(english:"openSUSE Security Update : glibc (openSUSE-SU-2012:0064-1)");
  script_summary(english:"Check for the glibc-5554 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Specially crafted time zone files could cause a heap overflow in glibc
(CVE-2009-5029)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=735850"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2012-01/msg00023.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glibc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nscd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nscd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/19");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"glibc-2.11.3-12.21.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"glibc-debuginfo-2.11.3-12.21.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"glibc-debugsource-2.11.3-12.21.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"glibc-devel-2.11.3-12.21.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"glibc-devel-debuginfo-2.11.3-12.21.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"glibc-html-2.11.3-12.21.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"glibc-i18ndata-2.11.3-12.21.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"glibc-info-2.11.3-12.21.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"glibc-locale-2.11.3-12.21.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"glibc-locale-debuginfo-2.11.3-12.21.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"glibc-obsolete-2.11.3-12.21.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"glibc-obsolete-debuginfo-2.11.3-12.21.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"glibc-profile-2.11.3-12.21.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"nscd-2.11.3-12.21.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"nscd-debuginfo-2.11.3-12.21.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"glibc-32bit-2.11.3-12.21.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"glibc-debuginfo-32bit-2.11.3-12.21.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"glibc-devel-32bit-2.11.3-12.21.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"glibc-devel-debuginfo-32bit-2.11.3-12.21.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"glibc-locale-32bit-2.11.3-12.21.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"glibc-locale-debuginfo-32bit-2.11.3-12.21.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"glibc-profile-32bit-2.11.3-12.21.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-32bit / glibc-devel / glibc-devel-32bit / glibc-html / etc");
}
