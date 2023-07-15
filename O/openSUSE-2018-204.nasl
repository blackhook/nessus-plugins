#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-204.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106965);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-15098", "CVE-2017-15099", "CVE-2017-7546", "CVE-2017-7547", "CVE-2017-7548", "CVE-2018-1053");

  script_name(english:"openSUSE Security Update : postgresql95 (openSUSE-2018-204)");
  script_summary(english:"Check for the openSUSE-2018-204 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for postgresql95 fixes the following issues :

Upate to PostgreSQL 9.5.11 :

Security issues fixed :

  - https://www.postgresql.org/docs/9.5/static/release-9-5-11.html 

  - CVE-2018-1053, boo#1077983: Ensure that all temporary
    files made by pg_upgrade are non-world-readable. 

  - boo#1079757: Rename pg_rewind's copy_file_range function
    to avoid conflict with new Linux system call of that
    name.

In version 9.5.10 :

  - https://www.postgresql.org/docs/9.5/static/release-9-5-10.html

  - CVE-2017-15098, boo#1067844: Memory disclosure in JSON
    functions.

  - CVE-2017-15099, boo#1067841: INSERT ... ON CONFLICT DO
    UPDATE fails to enforce SELECT privileges.

In version 9.5.9 :

  - https://www.postgresql.org/docs/9.5/static/release-9-5-9.html

  - Show foreign tables in
    information_schema.table_privileges view.

  - Clean up handling of a fatal exit (e.g., due to receipt
    of SIGTERM) that occurs while trying to execute a
    ROLLBACK of a failed transaction.

  - Remove assertion that could trigger during a fatal exit.

  - Correctly identify columns that are of a range type or
    domain type over a composite type or domain type being
    searched for.

  - Fix crash in pg_restore when using parallel mode and
    using a list file to select a subset of items to
    restore.

  - Change ecpg's parser to allow RETURNING clauses without
    attached C variables.

In version 9.5.8

  - https://www.postgresql.org/docs/9.5/static/release-9-5-8.html

  - CVE-2017-7547, boo#1051685: Further restrict visibility
    of pg_user_mappings.umoptions, to protect passwords
    stored as user mapping options.

  - CVE-2017-7546, boo#1051684: Disallow empty passwords in
    all password-based authentication methods.

  - CVE-2017-7548, boo#1053259: lo_put() function ignores
    ACLs."
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
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1067841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1067844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077983"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1079757"
  );
  # https://www.postgresql.org/docs/9.5/static/release-9-5-10.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/9.5/release-9-5-10.html"
  );
  # https://www.postgresql.org/docs/9.5/static/release-9-5-11.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/9.5/release-9-5-11.html"
  );
  # https://www.postgresql.org/docs/9.5/static/release-9-5-8.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/9.5/release-9-5-8.html"
  );
  # https://www.postgresql.org/docs/9.5/static/release-9-5-9.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/9.5/release-9-5-9.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql95 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/23");
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

if ( rpm_check(release:"SUSE42.3", reference:"postgresql95-9.5.11-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql95-contrib-9.5.11-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql95-contrib-debuginfo-9.5.11-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql95-debuginfo-9.5.11-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql95-debugsource-9.5.11-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql95-devel-9.5.11-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql95-devel-debuginfo-9.5.11-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql95-libs-debugsource-9.5.11-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql95-plperl-9.5.11-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql95-plperl-debuginfo-9.5.11-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql95-plpython-9.5.11-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql95-plpython-debuginfo-9.5.11-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql95-pltcl-9.5.11-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql95-pltcl-debuginfo-9.5.11-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql95-server-9.5.11-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql95-server-debuginfo-9.5.11-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"postgresql95-test-9.5.11-2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql95-devel / postgresql95-devel-debuginfo / etc");
}
