#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-89.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81139);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-9273");

  script_name(english:"openSUSE Security Update : hivex (openSUSE-SU-2015:0189-1)");
  script_summary(english:"Check for the openSUSE-2015-89 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"hivex was updated to fix a possible denial of service due to missing
size checks (bnc#908614)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=908614"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2015-02/msg00005.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected hivex packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hivex-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hivex-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hivex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libhivex0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libhivex0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-Win-Hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-Win-Hivex-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-hivex-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"hivex-1.3.8-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hivex-debuginfo-1.3.8-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hivex-debugsource-1.3.8-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hivex-devel-1.3.8-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libhivex0-1.3.8-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libhivex0-debuginfo-1.3.8-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"perl-Win-Hivex-1.3.8-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"perl-Win-Hivex-debuginfo-1.3.8-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-hivex-1.3.8-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-hivex-debuginfo-1.3.8-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hivex-1.3.10-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hivex-debuginfo-1.3.10-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hivex-debugsource-1.3.10-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hivex-devel-1.3.10-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libhivex0-1.3.10-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libhivex0-debuginfo-1.3.10-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"perl-Win-Hivex-1.3.10-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"perl-Win-Hivex-debuginfo-1.3.10-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-hivex-1.3.10-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-hivex-debuginfo-1.3.10-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "hivex / hivex-debuginfo / hivex-debugsource / hivex-devel / etc");
}
