#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-570.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(90982);
  script_version("2.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-2167", "CVE-2016-2168");

  script_name(english:"openSUSE Security Update : subversion (openSUSE-2016-570)");
  script_summary(english:"Check for the openSUSE-2016-570 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for subversion fixes the following issues :

  - CVE-2016-2167: mod_authz_svn: DoS in MOVE/COPY
    authorization check (bsc#976849)

  - CVE-2016-2168: svnserve/sasl may authenticate users
    using the wrong realm (bsc#976850)

The following non-security bugs were fixed :

  - bsc#969159: subversion dependencies did not enforce
    matching password store

  - bsc#911620: svnserve could not be started via YaST
    Service manager

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=911620"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=976849"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=976850"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected subversion packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsvn_auth_gnome_keyring-1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsvn_auth_gnome_keyring-1-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsvn_auth_kwallet-1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsvn_auth_kwallet-1-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"libsvn_auth_gnome_keyring-1-0-1.8.10-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsvn_auth_gnome_keyring-1-0-debuginfo-1.8.10-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsvn_auth_kwallet-1-0-1.8.10-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsvn_auth_kwallet-1-0-debuginfo-1.8.10-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"subversion-1.8.10-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"subversion-bash-completion-1.8.10-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"subversion-debuginfo-1.8.10-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"subversion-debugsource-1.8.10-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"subversion-devel-1.8.10-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"subversion-perl-1.8.10-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"subversion-perl-debuginfo-1.8.10-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"subversion-python-1.8.10-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"subversion-python-debuginfo-1.8.10-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"subversion-ruby-1.8.10-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"subversion-ruby-debuginfo-1.8.10-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"subversion-server-1.8.10-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"subversion-server-debuginfo-1.8.10-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"subversion-tools-1.8.10-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"subversion-tools-debuginfo-1.8.10-9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsvn_auth_gnome_keyring-1-0 / etc");
}
