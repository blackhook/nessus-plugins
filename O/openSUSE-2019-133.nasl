#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-133.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(121591);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-18500", "CVE-2018-18501", "CVE-2018-18505");

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-2019-133)");
  script_summary(english:"Check for the openSUSE-2019-133 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for MozillaFirefox, mozilla-nss fixes the following
issues: Security issues fixed :

  - CVE-2018-18500: Fixed a use-after-free parsing HTML5
    stream (boo#1122983).

  - CVE-2018-18505: Fixed a privilege escalation through IPC
    channel messages (boo#1122983).

  - CVE-2018-18501: Fixed multiple memory safety bugs
    (boo#1122983).

Non-security issue fixed :

  - Update mozilla-nss to version 3.36.7 as build
    dependency."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121255"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122983"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE42.3", reference:"libfreebl3-3.36.7-57.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libfreebl3-debuginfo-3.36.7-57.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsoftokn3-3.36.7-57.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsoftokn3-debuginfo-3.36.7-57.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mozilla-nss-3.36.7-57.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mozilla-nss-certs-3.36.7-57.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mozilla-nss-certs-debuginfo-3.36.7-57.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mozilla-nss-debuginfo-3.36.7-57.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mozilla-nss-debugsource-3.36.7-57.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mozilla-nss-devel-3.36.7-57.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mozilla-nss-sysinit-3.36.7-57.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mozilla-nss-sysinit-debuginfo-3.36.7-57.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mozilla-nss-tools-3.36.7-57.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mozilla-nss-tools-debuginfo-3.36.7-57.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"MozillaFirefox-60.5.0-128.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"MozillaFirefox-branding-upstream-60.5.0-128.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"MozillaFirefox-buildsymbols-60.5.0-128.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"MozillaFirefox-debuginfo-60.5.0-128.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"MozillaFirefox-debugsource-60.5.0-128.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"MozillaFirefox-devel-60.5.0-128.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"MozillaFirefox-translations-common-60.5.0-128.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"MozillaFirefox-translations-other-60.5.0-128.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libfreebl3-32bit-3.36.7-57.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.36.7-57.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsoftokn3-32bit-3.36.7-57.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.36.7-57.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"mozilla-nss-32bit-3.36.7-57.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.36.7-57.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.36.7-57.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.36.7-57.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.36.7-57.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.36.7-57.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libfreebl3 / libfreebl3-32bit / libfreebl3-debuginfo / etc");
}
