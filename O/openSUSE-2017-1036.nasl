#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1036.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103161);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_name(english:"openSUSE Security Update : libidn2 (openSUSE-2017-1036)");
  script_summary(english:"Check for the openSUSE-2017-1036 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libidn2 fixes the following issues :

  - integer overflow in bidi.c/_isBidi() could lead to
    unexpected behavior (boo#1056451)

  - integer overflow in puny_decode.c/decode_digit() could
    lead to unexpected behavior (boo#1056450)

libunistring was rebuilt to supply a -32bit package, a dependency for
libidn2-0-32bit (boo#1056981)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056450"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056981"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libidn2 packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libidn2-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libidn2-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libidn2-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libidn2-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libidn2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libidn2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libidn2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libidn2-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libunistring-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libunistring-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libunistring-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libunistring0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libunistring0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libunistring0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libunistring0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"libidn2-0-2.0.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libidn2-0-debuginfo-2.0.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libidn2-debugsource-2.0.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libidn2-devel-2.0.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libidn2-tools-2.0.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libidn2-tools-debuginfo-2.0.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libunistring-debugsource-0.9.3-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libunistring-devel-0.9.3-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libunistring0-0.9.3-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libunistring0-debuginfo-0.9.3-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libidn2-0-32bit-2.0.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libidn2-0-debuginfo-32bit-2.0.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libunistring-devel-32bit-0.9.3-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libunistring0-32bit-0.9.3-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libunistring0-debuginfo-32bit-0.9.3-25.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libidn2-0 / libidn2-0-32bit / libidn2-0-debuginfo / etc");
}
