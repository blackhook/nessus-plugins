#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1006.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117519);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-1000801");

  script_name(english:"openSUSE Security Update : okular (openSUSE-2018-1006)");
  script_summary(english:"Check for the openSUSE-2018-1006 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for okular fixes the following security issue :

  - CVE-2018-1000801: Prevent directory traversal
    vulnerability in function unpackDocumentArchive could
    have resulted in arbitrary file creation via a specially
    crafted Okular archive (bsc#1107591)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107591"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected okular packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:okular");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:okular-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:okular-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:okular-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:okular-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/17");
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
if (release !~ "^(SUSE15\.0|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"okular-17.12.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"okular-debuginfo-17.12.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"okular-debugsource-17.12.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"okular-devel-17.12.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"okular-lang-17.12.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"okular-17.04.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"okular-debuginfo-17.04.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"okular-debugsource-17.04.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"okular-devel-17.04.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"okular-lang-17.04.2-6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "okular / okular-debuginfo / okular-debugsource / okular-devel / etc");
}
