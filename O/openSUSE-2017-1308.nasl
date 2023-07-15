#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1308.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104771);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-16837");

  script_name(english:"openSUSE Security Update : tboot (openSUSE-2017-1308)");
  script_summary(english:"Check for the openSUSE-2017-1308 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for tboot fixes the following issues :

Security issues fixed :

  - CVE-2017-16837: Fix tbootfailed to validate a number of
    immutable function pointers, which could allow an
    attacker to bypass the chain of trust and execute
    arbitrary code (boo#1068390).

  - Make tboot package compatible with OpenSSL 1.1.0 for
    SLE-15 support (boo#1067229).

Bug fixes :

  - Update to new upstream version. See release notes for
    details (1.9.6; 1.9.5, FATE#321510; 1.9.4, FATE#320665;
    1.8.3, FATE#318542) :

  - https://sourceforge.net/p/tboot/code/ci/default/tree/CHANGELOG

  - Fix some gcc7 warnings that lead to errors.
    (boo#1041264)

  - Fix wrong pvops kernel config matching (boo#981948) 

  - Fix a excessive stack usage pattern that could lead to
    resets/crashes (boo#967441)

  - fixes a boot issue on Skylake (boo#964408)

  - Trim filler words from description; use modern macros
    over shell vars.

  - Add reproducible.patch to call gzip -n to make build
    fully reproducible."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1041264"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1067229"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068390"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=964408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967441"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=981948"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://sourceforge.net/p/tboot/code/ci/default/tree/CHANGELOG"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tboot packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tboot-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tboot-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/27");
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
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"tboot-20170711_1.9.6-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tboot-debuginfo-20170711_1.9.6-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tboot-debugsource-20170711_1.9.6-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tboot-20170711_1.9.6-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tboot-debuginfo-20170711_1.9.6-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tboot-debugsource-20170711_1.9.6-7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tboot / tboot-debuginfo / tboot-debugsource");
}
