#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1020.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103156);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-7546", "CVE-2017-7547", "CVE-2017-7548");

  script_name(english:"openSUSE Security Update : postgresql94 (openSUSE-2017-1020)");
  script_summary(english:"Check for the openSUSE-2017-1020 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for postgresql94 fixes the following issues :

  - CVE-2017-7547: Further restrict visibility of
    pg_user_mappings.umoptions, to protect passwords stored
    as user mapping options. (bsc#1051685)

  - CVE-2017-7546: Disallow empty passwords in all
    password-based authentication methods. (bsc#1051684)

  - CVE-2017-7548: lo_put() function ignores ACLs.
    (bsc#1053259)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053259"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql94 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql94");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql94-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql94-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql94-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql94-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql94-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql94-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql94-libs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql94-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql94-plperl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql94-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql94-plpython-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql94-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql94-pltcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql94-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql94-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql94-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/13");
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

if ( rpm_check(release:"SUSE42.2", reference:"postgresql94-9.4.13-9.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"postgresql94-contrib-9.4.13-9.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"postgresql94-contrib-debuginfo-9.4.13-9.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"postgresql94-debuginfo-9.4.13-9.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"postgresql94-debugsource-9.4.13-9.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"postgresql94-devel-9.4.13-9.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"postgresql94-devel-debuginfo-9.4.13-9.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"postgresql94-libs-debugsource-9.4.13-9.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"postgresql94-plperl-9.4.13-9.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"postgresql94-plperl-debuginfo-9.4.13-9.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"postgresql94-plpython-9.4.13-9.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"postgresql94-plpython-debuginfo-9.4.13-9.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"postgresql94-pltcl-9.4.13-9.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"postgresql94-pltcl-debuginfo-9.4.13-9.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"postgresql94-server-9.4.13-9.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"postgresql94-server-debuginfo-9.4.13-9.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"postgresql94-test-9.4.13-9.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql94-9.4.13-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql94-contrib-9.4.13-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql94-contrib-debuginfo-9.4.13-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql94-debuginfo-9.4.13-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql94-debugsource-9.4.13-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql94-devel-9.4.13-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql94-devel-debuginfo-9.4.13-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql94-libs-debugsource-9.4.13-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql94-plperl-9.4.13-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql94-plperl-debuginfo-9.4.13-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql94-plpython-9.4.13-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql94-plpython-debuginfo-9.4.13-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql94-pltcl-9.4.13-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql94-pltcl-debuginfo-9.4.13-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql94-server-9.4.13-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql94-server-debuginfo-9.4.13-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql94-test-9.4.13-12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql94-devel / postgresql94-devel-debuginfo / etc");
}
