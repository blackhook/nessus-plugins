#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-5.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105638);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-14919", "CVE-2017-15896", "CVE-2017-3735", "CVE-2017-3736", "CVE-2017-3737", "CVE-2017-3738");

  script_name(english:"openSUSE Security Update : nodejs4 (openSUSE-2018-5)");
  script_summary(english:"Check for the openSUSE-2018-5 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for nodejs4 fixes the following issues :

Security issues fixed :

  - CVE-2017-15896: Vulnerable to CVE-2017-3737 due to
    embedded OpenSSL (bsc#1072322).

  - CVE-2017-14919: Embedded zlib issue could cause a DoS
    via specific windowBits value.

  - CVE-2017-3738: Embedded OpenSSL is vulnerable to
    rsaz_1024_mul_avx2 overflow bug on x86_64.

  - CVE-2017-3736: Embedded OpenSSL is vulnerable to
    bn_sqrx8x_internal carry bug on x86_64 (bsc#1066242).

  - CVE-2017-3735: Embedded OpenSSL is vulnerable to
    malformed X.509 IPAdressFamily that could cause OOB read
    (bsc#1056058).

Bug fixes :

  - Update to release 4.8.7 (bsc#1072322) :

  - https://nodejs.org/en/blog/vulnerability/december-2017-security-releases/

  - https://nodejs.org/en/blog/release/v4.8.7/

  - https://nodejs.org/en/blog/release/v4.8.6/

  - https://nodejs.org/en/blog/release/v4.8.5/

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1072322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://nodejs.org/en/blog/release/v4.8.5/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://nodejs.org/en/blog/release/v4.8.6/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://nodejs.org/en/blog/release/v4.8.7/"
  );
  # https://nodejs.org/en/blog/vulnerability/december-2017-security-releases/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?23d8f9db"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nodejs4 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs4-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:npm4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/08");
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
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"nodejs4-4.8.7-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"nodejs4-debuginfo-4.8.7-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"nodejs4-debugsource-4.8.7-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"nodejs4-devel-4.8.7-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"npm4-4.8.7-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nodejs4-4.8.7-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nodejs4-debuginfo-4.8.7-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nodejs4-debugsource-4.8.7-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nodejs4-devel-4.8.7-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"npm4-4.8.7-11.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nodejs4 / nodejs4-debuginfo / nodejs4-debugsource / nodejs4-devel / etc");
}
