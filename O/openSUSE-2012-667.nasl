#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-667.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(74769);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2012-2143", "CVE-2012-2655", "CVE-2012-3488", "CVE-2012-3489");

  script_name(english:"openSUSE Security Update : postgresql / postgresql-libs (openSUSE-SU-2012:1288-1)");
  script_summary(english:"Check for the openSUSE-2012-667 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Security and bugfix release 9.1.5 :

  - Ignore SECURITY DEFINER and SET attributes for a
    procedural language's call handler (CVE-2012-2655)
    bnc#765069

  - Fix incorrect password transformation in
    'contrib/pgcrypto''s DES crypt() function
    (CVE-2012-2143) bnc#766799

  - Prevent access to external files/URLs via
    'contrib/xml2''s xslt_process() (CVE-2012-3488)
    bnc#776523

  - Prevent access to external files/URLs via XML entity
    references (CVE-2012-3489) bnc#776524

  - See the release notes for the rest of the changes:
    http://www.postgresql.org/docs/9.1/static/release.html
    /usr/share/doc/packages/postgresql/HISTORY"
  );
  # http://www.postgresql.org/docs/9.1/static/release.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/9.1/release.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=765069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=766797"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=776523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=776524"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2012-10/msg00013.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql / postgresql-libs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-devel-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-libs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-plperl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-plpython-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-pltcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"libecpg6-9.1.5-7.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libecpg6-debuginfo-9.1.5-7.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libpq5-9.1.5-7.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libpq5-debuginfo-9.1.5-7.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"postgresql-9.1.5-7.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"postgresql-contrib-9.1.5-7.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"postgresql-contrib-debuginfo-9.1.5-7.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"postgresql-debuginfo-9.1.5-7.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"postgresql-debugsource-9.1.5-7.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"postgresql-devel-9.1.5-7.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"postgresql-devel-debuginfo-9.1.5-7.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"postgresql-libs-debugsource-9.1.5-7.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"postgresql-plperl-9.1.5-7.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"postgresql-plperl-debuginfo-9.1.5-7.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"postgresql-plpython-9.1.5-7.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"postgresql-plpython-debuginfo-9.1.5-7.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"postgresql-pltcl-9.1.5-7.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"postgresql-pltcl-debuginfo-9.1.5-7.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"postgresql-server-9.1.5-7.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"postgresql-server-debuginfo-9.1.5-7.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libpq5-32bit-9.1.5-7.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libpq5-debuginfo-32bit-9.1.5-7.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"postgresql-devel-32bit-9.1.5-7.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"postgresql-devel-debuginfo-32bit-9.1.5-7.8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libecpg6 / libecpg6-debuginfo / libpq5-32bit / libpq5 / etc");
}
