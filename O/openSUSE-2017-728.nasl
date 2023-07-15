#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-728.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101130);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2013-7038", "CVE-2013-7039");

  script_name(english:"openSUSE Security Update : libmicrohttpd (openSUSE-2017-728)");
  script_summary(english:"Check for the openSUSE-2017-728 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libmicrohttpd fixes the following issues :

  - CVE-2013-7038: The MHD_http_unescape function in
    libmicrohttpd might have allowed remote attackers to
    obtain sensitive information or cause a denial of
    service (crash) via unspecified vectors that trigger an
    out-of-bounds read. (bsc#854443)

  - CVE-2013-7039: Stack-based buffer overflow in the
    MHD_digest_auth_check function in libmicrohttpd, when
    MHD_OPTION_CONNECTION_MEMORY_LIMIT is set to a large
    value, allowed remote attackers to cause a denial of
    service (crash) or possibly execute arbitrary code via a
    long URI in an authentication header. (bsc#854443)

  - Fixed various bugs found during a 2017 audit, which are
    more hardening measures and not security issues.
    (bsc#1041216)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1041216"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=854443"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libmicrohttpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmicrohttpd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmicrohttpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmicrohttpd10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmicrohttpd10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmicrospdy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmicrospdy0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmicrospdy0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:microspdy2http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:microspdy2http-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/30");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"libmicrohttpd-debugsource-0.9.30-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmicrohttpd-devel-0.9.30-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmicrohttpd10-0.9.30-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmicrohttpd10-debuginfo-0.9.30-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmicrospdy-devel-0.9.30-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmicrospdy0-0.9.30-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmicrospdy0-debuginfo-0.9.30-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"microspdy2http-0.9.30-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"microspdy2http-debuginfo-0.9.30-5.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmicrohttpd-debugsource / libmicrohttpd-devel / libmicrohttpd10 / etc");
}
