#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1624.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119951);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-15468", "CVE-2018-15469", "CVE-2018-15470", "CVE-2018-18883", "CVE-2018-19961", "CVE-2018-19962", "CVE-2018-19965", "CVE-2018-19966", "CVE-2018-3646");

  script_name(english:"openSUSE Security Update : xen (openSUSE-2018-1624) (Foreshadow)");
  script_summary(english:"Check for the openSUSE-2018-1624 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for xen fixes the following issues :

Update to Xen 4.10.2 bug fix release (bsc#1027519).

Security vulnerabilities fixed :

  - CVE-2018-19961, CVE-2018-19962: Fixed an issue related
    to insufficient TLB flushing with AMD IOMMUs, which
    potentially allowed a guest to escalate its privileges,
    may cause a Denial of Service (DoS) affecting the entire
    host, or may be able to access data it is not supposed
    to access. (XSA-275) (bsc#1115040)

  - CVE-2018-19965: Fixed an issue related to the INVPCID
    instruction in case non-canonical addresses are
    accessed, which may allow a guest to cause Xen to crash,
    resulting in a Denial of Service (DoS) affecting the
    entire host. (XSA-279) (bsc#1115045)

  - CVE-2018-19966: Fixed an issue related to a previous fix
    for XSA-240, which conflicted with shadow paging and
    allowed a guest to cause Xen to crash, resulting in a
    Denial of Service (DoS). (XSA-280) (bsc#1115047)

  - CVE-2018-18883: Fixed an issue related to inproper
    restriction of nested VT-x, which allowed a guest to
    cause Xen to crash, resulting in a Denial of Service
    (DoS). (XSA-278) (bsc#1114405)

  - CVE-2018-15468: Fixed incorrect MSR_DEBUGCTL handling,
    which allowed guests to enable Branch Trace Store and
    may cause a Denial of Service (DoS) of the entire host.
    (XSA-269) (bsc#1103276)

  - CVE-2018-15469: Fixed use of v2 grant tables on ARM,
    which were not properly implemented and may cause a
    Denial of Service (DoS). (XSA-268) (bsc#1103275)

  - CVE-2018-15470: Fixed an issue in the logic in
    oxenstored for handling writes, which allowed a guest to
    write memory unbounded leading to system-wide Denial of
    Service (DoS). (XSA-272) (bsc#1103279)

  - CVE-2018-3646: Mitigations for VMM aspects of L1
    Terminal Fault (XSA-273) (bsc#1091107)

Other bugs fixed :

  - Fixed an issue related to a domU hang on SLE12-SP3 HV
    (bsc#1108940)

  - Fixed an issue with xpti=no-dom0 not working as expected
    (bsc#1105528)

  - Fixed a kernel oops related to fs/dcache.c called by
    d_materialise_unique() (bsc#1094508)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1078292"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094508"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103275"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108940"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114405"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115045"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115047"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/29");
  script_set_attribute(attribute:"in_the_news", value:"true");
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

if ( rpm_check(release:"SUSE15.0", reference:"xen-debugsource-4.10.2_04-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"xen-devel-4.10.2_04-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"xen-libs-4.10.2_04-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"xen-libs-debuginfo-4.10.2_04-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"xen-tools-domU-4.10.2_04-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"xen-tools-domU-debuginfo-4.10.2_04-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"xen-4.10.2_04-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"xen-doc-html-4.10.2_04-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"xen-libs-32bit-4.10.2_04-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"xen-libs-32bit-debuginfo-4.10.2_04-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"xen-tools-4.10.2_04-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"xen-tools-debuginfo-4.10.2_04-lp150.2.12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-debugsource / xen-devel / xen-doc-html / xen-libs / etc");
}
