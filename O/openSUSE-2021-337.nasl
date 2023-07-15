#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-337.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(146831);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id("CVE-2020-25694", "CVE-2020-25695", "CVE-2020-25696");

  script_name(english:"openSUSE Security Update : postgresql / postgresql13 (openSUSE-2021-337)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for postgresql, postgresql13 fixes the following issues :

This update ships postgresql13.

Upgrade to version 13.1 :

  - CVE-2020-25695, bsc#1178666: Block DECLARE CURSOR ...
    WITH HOLD and firing of deferred triggers within index
    expressions and materialized view queries.

  - CVE-2020-25694, bsc#1178667: a) Fix usage of complex
    connection-string parameters in pg_dump, pg_restore,
    clusterdb, reindexdb, and vacuumdb. b) When psql's
    \connect command re-uses connection parameters, ensure
    that all non-overridden parameters from a previous
    connection string are re-used.

  - CVE-2020-25696, bsc#1178668: Prevent psql's \gset
    command from modifying specially-treated variables.

  - Fix recently-added timetz test case so it works when the
    USA is not observing daylight savings time. (obsoletes
    postgresql-timetz.patch)

- https://www.postgresql.org/about/news/2111/

- https://www.postgresql.org/docs/13/release-13-1.html

Initial packaging of PostgreSQL 13 :

- https://www.postgresql.org/about/news/2077/

- https://www.postgresql.org/docs/13/release-13.html

  - bsc#1178961: %ghost the symlinks to pg_config and ecpg.

Changes in postgresql wrapper package :

  - Bump major version to 13.

  - We also transfer PostgreSQL 9.4.26 to the new package
    layout in SLE12-SP2 and newer. Reflect this in the
    conflict with postgresql94.

  - Also conflict with PostgreSQL versions before 9.

  - Conflicting with older versions is not limited to SLE.

This update was imported from the SUSE:SLE-15-SP2:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178667");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178668");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178961");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/about/news/2077/");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/about/news/2111/");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/13/release-13-1.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/13/release-13.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected postgresql / postgresql13 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25696");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-25695");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-llvmjit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"postgresql-13-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql-contrib-13-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql-devel-13-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql-llvmjit-13-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql-plperl-13-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql-plpython-13-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql-pltcl-13-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql-server-13-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql-server-devel-13-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql-test-13-lp152.3.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / postgresql-contrib / postgresql-devel / etc");
}
