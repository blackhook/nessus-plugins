#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-355.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(83394);
  script_version("2.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2015-3146");

  script_name(english:"openSUSE Security Update : libssh (openSUSE-2015-355)");
  script_summary(english:"Check for the openSUSE-2015-355 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libssh was updated to fix one security issue.

The following vulnerability was fixed :

  - CVE-2015-3146: Specially crafted packages inserted into
    a connection could have lead to a client or server
    process crash via a NULL pointer dereference."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=928323"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libssh packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssh-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssh-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssh4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssh4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssh4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssh4-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE13.1", reference:"libssh-debugsource-0.5.5-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libssh-devel-0.5.5-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libssh4-0.5.5-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libssh4-debuginfo-0.5.5-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libssh4-32bit-0.5.5-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libssh4-debuginfo-32bit-0.5.5-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libssh-debugsource-0.6.3-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libssh-devel-0.6.3-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libssh4-0.6.3-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libssh4-debuginfo-0.6.3-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libssh4-32bit-0.6.3-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libssh4-debuginfo-32bit-0.6.3-2.7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libssh-debugsource / libssh-devel / libssh4 / libssh4-32bit / etc");
}
