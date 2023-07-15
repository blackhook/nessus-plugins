#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-849.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111630);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-5807", "CVE-2018-5810", "CVE-2018-5811", "CVE-2018-5812", "CVE-2018-5813", "CVE-2018-5815");

  script_name(english:"openSUSE Security Update : libraw (openSUSE-2018-849)");
  script_summary(english:"Check for the openSUSE-2018-849 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libraw fixes the following issues :

The following security vulnerabilities were addressed :

  - CVE-2018-5813: Fixed an error within the
    'parse_minolta()' function (dcraw/dcraw.c) that could be
    exploited to trigger an infinite loop via a specially
    crafted file. This could be exploited to cause a
    DoS.(boo#1103200).

  - CVE-2018-5815: Fixed an integer overflow in the
    internal/dcraw_common.cpp:parse_qt() function, that
    could be exploited to cause an infinite loop via a
    specially crafted Apple QuickTime file. (boo#1103206)

  - CVE-2018-5810: Fixed an error within the
    rollei_load_raw() function (internal/dcraw_common.cpp)
    that could be exploited to cause a heap-based buffer
    overflow and subsequently cause a crash. (boo#1103353)

  - CVE-2018-5811: Fixed an error within the
    nikon_coolscan_load_raw() function
    (internal/dcraw_common.cpp) that could be exploited to
    cause an out-of-bounds read memory access and
    subsequently cause a crash. (boo#1103359)

  - CVE-2018-5812: Fixed another error within the
    nikon_coolscan_load_raw() function
    (internal/dcraw_common.cpp) that could be exploited to
    trigger a NULL pointer dereference. (boo#1103360)

  - CVE-2018-5807: Fixed an error within the
    samsung_load_raw() function (internal/dcraw_common.cpp)
    that could be exploited to cause an out-of-bounds read
    memory access and subsequently cause a crash.
    (boo#1103361)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103200"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103206"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103359"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103360"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103361"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libraw packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libraw-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libraw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libraw-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libraw-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libraw-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libraw15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libraw15-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/10");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"libraw-debugsource-0.17.1-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libraw-devel-0.17.1-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libraw-devel-static-0.17.1-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libraw-tools-0.17.1-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libraw-tools-debuginfo-0.17.1-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libraw15-0.17.1-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libraw15-debuginfo-0.17.1-23.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libraw-debugsource / libraw-devel / libraw-devel-static / etc");
}
