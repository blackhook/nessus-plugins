#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-696.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110955);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-1115");

  script_name(english:"openSUSE Security Update : postgresql95 (openSUSE-2018-696)");
  script_summary(english:"Check for the openSUSE-2018-696 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for postgresql95 fixes the following issues :

  - Update to PostgreSQL 9.5.13 :

  - https://www.postgresql.org/docs/9.5/static/release-9-5-13.html
A dump/restore is not required for those running 9.5.X.
However, if the function marking mistakes mentioned belowpg_logfile_rotate
affect you, you will want to take steps to correct your
database catalogs.
The functions query_to_xml, cursor_to_xml, cursor_to_xmlschema,
query_to_xmlschema, and query_to_xml_and_xmlschema should be
marked volatile because they execute user-supplied queries
that might contain volatile operations. They were not,
leading to a risk of incorrect query optimization. This has
been repaired for new installations by correcting the initial
catalog data, but existing installations will continue to
contain the incorrect markings. Practical use of these
functions seems to pose little hazard, but in case of trouble,
it can be fixed by manually updating these functions' pg_proc
entries, for example: ALTER FUNCTION
pg_catalog.query_to_xml(text, boolean, boolean, text) VOLATILE.
    (Note that that will need to be done in each database of the
installation.) Another option is to pg_upgrade the database to
a version containing the corrected initial data.
Security issue fixed :

  - CVE-2018-1115: Remove public execute privilege from
    contrib/adminpack's pg_logfile_rotate() function
    pg_logfile_rotate() is a deprecated wrapper for the core
    function pg_rotate_logfile(). When that function was
    changed to rely on SQL privileges for access control
    rather than a hard-coded superuser check,
    pg_logfile_rotate() should have been updated as well,
    but the need for this was missed. Hence, if adminpack is
    installed, any user could request a logfile rotation,
    creating a minor security issue. After installing this
    update, administrators should update adminpack by
    performing ALTER EXTENSION adminpack UPDATE in each
    database in which adminpack is installed. (bsc#1091610)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091610"
  );
  # https://www.postgresql.org/docs/9.5/static/release-9-5-13.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/9.5/release-9-5-13.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql95 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql95");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql95-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql95-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql95-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql95-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql95-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql95-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql95-libs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql95-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql95-plperl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql95-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql95-plpython-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql95-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql95-pltcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql95-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql95-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql95-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/09");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"postgresql95-9.5.13-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql95-contrib-9.5.13-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql95-contrib-debuginfo-9.5.13-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql95-debuginfo-9.5.13-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql95-debugsource-9.5.13-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql95-devel-9.5.13-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql95-devel-debuginfo-9.5.13-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql95-libs-debugsource-9.5.13-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql95-plperl-9.5.13-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql95-plperl-debuginfo-9.5.13-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql95-plpython-9.5.13-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql95-plpython-debuginfo-9.5.13-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql95-pltcl-9.5.13-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql95-pltcl-debuginfo-9.5.13-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql95-server-9.5.13-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql95-server-debuginfo-9.5.13-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql95-test-9.5.13-2.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql95-devel / postgresql95-devel-debuginfo / etc");
}
