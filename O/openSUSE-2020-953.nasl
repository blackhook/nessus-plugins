#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-953.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(138734);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/24");

  script_cve_id("CVE-2020-12402");

  script_name(english:"openSUSE Security Update : mozilla-nss (openSUSE-2020-953)");
  script_summary(english:"Check for the openSUSE-2020-953 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for mozilla-nss fixes the following issues :

mozilla-nss was updated to version 3.53.1

  - CVE-2020-12402: Fixed a potential side channel attack
    during RSA key generation (bsc#1173032)

  - Fixed various FIPS issues in libfreebl3 which were
    causing segfaults in the test suite of chrony
    (bsc#1168669).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173032"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected mozilla-nss packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12402");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-hmac-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-hmac-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"libfreebl3-3.53.1-lp151.2.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libfreebl3-debuginfo-3.53.1-lp151.2.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libfreebl3-hmac-3.53.1-lp151.2.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsoftokn3-3.53.1-lp151.2.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsoftokn3-debuginfo-3.53.1-lp151.2.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsoftokn3-hmac-3.53.1-lp151.2.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nss-3.53.1-lp151.2.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nss-certs-3.53.1-lp151.2.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nss-certs-debuginfo-3.53.1-lp151.2.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nss-debuginfo-3.53.1-lp151.2.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nss-debugsource-3.53.1-lp151.2.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nss-devel-3.53.1-lp151.2.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nss-sysinit-3.53.1-lp151.2.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nss-sysinit-debuginfo-3.53.1-lp151.2.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nss-tools-3.53.1-lp151.2.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nss-tools-debuginfo-3.53.1-lp151.2.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libfreebl3-32bit-3.53.1-lp151.2.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libfreebl3-32bit-debuginfo-3.53.1-lp151.2.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libfreebl3-hmac-32bit-3.53.1-lp151.2.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libsoftokn3-32bit-3.53.1-lp151.2.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libsoftokn3-32bit-debuginfo-3.53.1-lp151.2.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libsoftokn3-hmac-32bit-3.53.1-lp151.2.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"mozilla-nss-32bit-3.53.1-lp151.2.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"mozilla-nss-32bit-debuginfo-3.53.1-lp151.2.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.53.1-lp151.2.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-debuginfo-3.53.1-lp151.2.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.53.1-lp151.2.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-debuginfo-3.53.1-lp151.2.26.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libfreebl3 / libfreebl3-debuginfo / libfreebl3-hmac / libsoftokn3 / etc");
}
