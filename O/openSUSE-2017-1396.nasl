#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1396.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105366);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-0741", "CVE-2016-4992", "CVE-2016-5405", "CVE-2017-2591", "CVE-2017-2668", "CVE-2017-7551");

  script_name(english:"openSUSE Security Update : 389-ds (openSUSE-2017-1396)");
  script_summary(english:"Check for the openSUSE-2017-1396 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for 389-ds fixes the following issues :

  - CVE-2017-7551: 389-ds-base: Password brute-force
    possible for locked account due to different return
    codes (bsc#1051997)

  - CVE-2016-4992: 389-ds: Information disclosure via
    repeated use of LDAP ADD operation (bsc#997256)

  - CVE-2016-5405: 389-ds: Password verification vulnerable
    to timing attack (bsc#1007004)

  - CVE-2017-2591: 389-ds-base: Heap buffer overflow in
    uiduniq.c (bsc#1020670)

  - CVE-2017-2668 389-ds Remote crash via crafted LDAP
    messages (bsc#1069067)

  - CVE-2016-0741: 389-ds: worker threads do not detect
    abnormally closed connections causing DoS (bsc#1069074)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007004"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051997"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069074"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=997256"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected 389-ds packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:389-ds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:389-ds-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:389-ds-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:389-ds-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/19");
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

if ( rpm_check(release:"SUSE42.2", reference:"389-ds-1.3.4.5-5.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"389-ds-debuginfo-1.3.4.5-5.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"389-ds-debugsource-1.3.4.5-5.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"389-ds-devel-1.3.4.5-5.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"389-ds-1.3.4.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"389-ds-debuginfo-1.3.4.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"389-ds-debugsource-1.3.4.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"389-ds-devel-1.3.4.5-8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "389-ds / 389-ds-debuginfo / 389-ds-debugsource / 389-ds-devel");
}
