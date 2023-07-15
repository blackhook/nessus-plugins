#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-487.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109936);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-10992");

  script_name(english:"openSUSE Security Update : lilypond (openSUSE-2018-487)");
  script_summary(english:"Check for the openSUSE-2018-487 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for lilypond fixes the following issues :

  - CVE-2018-10992: lilypond: Does not validate strings
    before launching the program specified by the BROWSER
    environment variable, which allows remote attackers to
    conduct argument-injection attacks (bsc#1093056)

  - packages do not build reproducibly from unsorted input
    (bsc#1041090)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1041090"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093056"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected lilypond packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lilypond");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lilypond-century-schoolbook-l-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lilypond-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lilypond-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lilypond-doc-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lilypond-doc-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lilypond-doc-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lilypond-doc-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lilypond-doc-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lilypond-doc-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lilypond-doc-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lilypond-doc-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lilypond-doc-zh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lilypond-emmentaler-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lilypond-fonts-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/21");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"lilypond-2.18.2-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"lilypond-century-schoolbook-l-fonts-2.18.2-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"lilypond-debuginfo-2.18.2-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"lilypond-debugsource-2.18.2-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"lilypond-doc-cs-2.18.2-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"lilypond-doc-de-2.18.2-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"lilypond-doc-es-2.18.2-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"lilypond-doc-fr-2.18.2-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"lilypond-doc-hu-2.18.2-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"lilypond-doc-it-2.18.2-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"lilypond-doc-ja-2.18.2-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"lilypond-doc-nl-2.18.2-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"lilypond-doc-zh-2.18.2-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"lilypond-emmentaler-fonts-2.18.2-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"lilypond-fonts-common-2.18.2-7.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lilypond-doc-cs / lilypond-doc-de / lilypond-doc-es / etc");
}
