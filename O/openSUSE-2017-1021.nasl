#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1021.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103157);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-7546", "CVE-2017-7547", "CVE-2017-7548");

  script_name(english:"openSUSE Security Update : postgresql96 (openSUSE-2017-1021)");
  script_summary(english:"Check for the openSUSE-2017-1021 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for postgresql96 fixes the following issues :

  - CVE-2017-7547: Further restrict visibility of
    pg_user_mappings.umoptions, to protect passwords stored
    as user mapping options. (bsc#1051685)

  - CVE-2017-7546: Disallow empty passwords in all
    password-based authentication methods. (bsc#1051684)

  - CVE-2017-7548: lo_put() function ignores ACLs.
    (bsc#1053259)

The changelog for this release is here:
&#9;https://www.postgresql.org/docs/9.6/static/release-9-6-4.html

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
  # https://www.postgresql.org/docs/9.6/static/release-9-6-4.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/9.6/release-9-6-4.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql96 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-libs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-plperl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-plpython-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-pltcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE42.2", reference:"libecpg6-9.6.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libecpg6-debuginfo-9.6.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpq5-9.6.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpq5-debuginfo-9.6.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"postgresql96-9.6.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"postgresql96-contrib-9.6.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"postgresql96-contrib-debuginfo-9.6.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"postgresql96-debuginfo-9.6.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"postgresql96-debugsource-9.6.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"postgresql96-devel-9.6.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"postgresql96-devel-debuginfo-9.6.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"postgresql96-libs-debugsource-9.6.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"postgresql96-plperl-9.6.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"postgresql96-plperl-debuginfo-9.6.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"postgresql96-plpython-9.6.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"postgresql96-plpython-debuginfo-9.6.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"postgresql96-pltcl-9.6.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"postgresql96-pltcl-debuginfo-9.6.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"postgresql96-server-9.6.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"postgresql96-server-debuginfo-9.6.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"postgresql96-test-9.6.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libecpg6-32bit-9.6.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libecpg6-debuginfo-32bit-9.6.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpq5-32bit-9.6.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpq5-debuginfo-32bit-9.6.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libecpg6-9.6.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libecpg6-debuginfo-9.6.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpq5-9.6.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpq5-debuginfo-9.6.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql96-9.6.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql96-contrib-9.6.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql96-contrib-debuginfo-9.6.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql96-debuginfo-9.6.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql96-debugsource-9.6.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql96-devel-9.6.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql96-devel-debuginfo-9.6.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql96-libs-debugsource-9.6.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql96-plperl-9.6.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql96-plperl-debuginfo-9.6.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql96-plpython-9.6.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql96-plpython-debuginfo-9.6.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql96-pltcl-9.6.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql96-pltcl-debuginfo-9.6.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql96-server-9.6.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql96-server-debuginfo-9.6.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql96-test-9.6.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libecpg6-32bit-9.6.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libecpg6-debuginfo-32bit-9.6.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libpq5-32bit-9.6.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libpq5-debuginfo-32bit-9.6.4-6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libecpg6-32bit / libecpg6 / libecpg6-debuginfo-32bit / etc");
}
