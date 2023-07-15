#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1279.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118449);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-1000622");

  script_name(english:"openSUSE Security Update : rust (openSUSE-2018-1279)");
  script_summary(english:"Check for the openSUSE-2018-1279 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for rust fixes the following issues :

  - CVE-2018-1000622: rustdoc loads plugins from
    world-writable directory allowing for arbitrary code
    execution This patch consists of requiring
    `--plugin-path` to be passed whenever `--plugin` is
    passed Note that rustdoc plugins will be removed
    entirely on 1.28.0 (bsc#1100691).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100691"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected rust packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rust");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rust-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rust-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rust-gdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rust-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rust-std");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rust-std-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/26");
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
if (ourarch !~ "^(i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"rust-1.24.1-lp150.2.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rust-debuginfo-1.24.1-lp150.2.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rust-debugsource-1.24.1-lp150.2.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rust-gdb-1.24.1-lp150.2.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rust-src-1.24.1-lp150.2.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rust-std-1.24.1-lp150.2.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rust-std-debuginfo-1.24.1-lp150.2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rust / rust-debuginfo / rust-debugsource / rust-gdb / rust-src / etc");
}
