#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1228.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(139765);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2020-14349", "CVE-2020-14350");
  script_xref(name:"IAVB", value:"2020-B-0047-S");

  script_name(english:"openSUSE Security Update : postgresql / postgresql96 / postgresql10 / etc (openSUSE-2020-1228)");
  script_summary(english:"Check for the openSUSE-2020-1228 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for postgresql, postgresql96, postgresql10, postgresql12
fixes the following issues :

Postgresql12 was updated to 12.3 (bsc#1171924).

- https://www.postgresql.org/about/news/2038/

- https://www.postgresql.org/docs/12/release-12-3.html

  - Let postgresqlXX conflict with postgresql-noarch <
    12.0.1 to get a clean and complete cutover to the new
    packaging schema.

Also changed in the postgresql wrapper package :

  - Bump version to 12.0.1, so that the binary packages also
    have a cut-point to conflict with.

  - Conflict with versions of the binary packages prior to
    the May 2020 update, because we changed the package
    layout at that point and need a clean cutover.

  - Bump package version to 12, but leave default at 10 for
    SLE-15 and SLE-15-SP1.

postgresql11 was updated to 11.9 :

  - CVE-2020-14349, bsc#1175193: Set a secure search_path in
    logical replication walsenders and apply workers

  - CVE-2020-14350, bsc#1175194: Make contrib modules'
    installation scripts more secure.

- https://www.postgresql.org/docs/11/release-11-9.html

  - Pack the /usr/lib/postgresql symlink only into the main
    package.

postgresql11 was updated to 11.8 (bsc#1171924).

  - https://www.postgresql.org/about/news/2038/

  - https://www.postgresql.org/docs/11/release-11-8.html

  - Unify the spec file to work across all current
    PostgreSQL versions to simplify future maintenance.

  - Move from the 'libs' build flavour to a 'mini' package
    that will only be used inside the build service and not
    get shipped, to avoid confusion with the debuginfo
    packages (bsc#1148643).

postgresql10 was updated to 10.13 (bsc#1171924).

- https://www.postgresql.org/about/news/2038/

- https://www.postgresql.org/docs/10/release-10-13.html

  - Unify the spec file to work across all current
    PostgreSQL versions to simplify future maintenance.

  - Move from the 'libs' build flavour to a 'mini' package
    that will only be used inside the build service and not
    get shipped, to avoid confusion with the debuginfo
    packages (bsc#1148643).

postgresql96 was updated to 9.6.19 :

  - CVE-2020-14350, boo#1175194: Make contrib modules'
    installation scripts more secure.

  - https://www.postgresql.org/docs/9.6/release-9-6-19.html

  - Pack the /usr/lib/postgresql symlink only into the main
    package.

  - Let postgresqlXX conflict with postgresql-noarch <
    12.0.1 to get a clean and complete cutover to the new
    packaging schema.

  - update to 9.6.18 (boo#1171924).
    https://www.postgresql.org/about/news/2038/
    https://www.postgresql.org/docs/9.6/release-9-6-18.html

  - Unify the spec file to work across all current
    PostgreSQL versions to simplify future maintenance.

  - Move from the 'libs' build flavour to a 'mini' package
    that will only be used inside the build service and not
    get shipped, to avoid confusion with the debuginfo
    packages (boo#1148643).

This update was imported from the SUSE:SLE-15-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171924"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175193"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175194"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/about/news/2038/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/10/release-10-13.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/11/release-11-8.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/11/release-11-9.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/12/release-12-3.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/9.6/release-9-6-18.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/9.6/release-9-6-19.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected postgresql / postgresql96 / postgresql10 / etc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14349");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-plperl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-plpython-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-pltcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql11-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql11-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql11-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql11-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql11-llvmjit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql11-llvmjit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql11-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql11-plperl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql11-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql11-plpython-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql11-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql11-pltcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql11-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql11-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql11-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql11-server-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql11-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-llvmjit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-llvmjit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-plperl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-plpython-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-pltcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-server-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-plperl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-plpython-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-pltcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql96-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"libecpg6-12.3-lp152.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libecpg6-debuginfo-12.3-lp152.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libpq5-12.3-lp152.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libpq5-debuginfo-12.3-lp152.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql-12.0.1-lp152.3.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql-contrib-12.0.1-lp152.3.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql-devel-12.0.1-lp152.3.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql-llvmjit-12.0.1-lp152.3.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql-plperl-12.0.1-lp152.3.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql-plpython-12.0.1-lp152.3.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql-pltcl-12.0.1-lp152.3.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql-server-12.0.1-lp152.3.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql-server-devel-12.0.1-lp152.3.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql-test-12.0.1-lp152.3.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql10-10.13-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql10-contrib-10.13-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql10-contrib-debuginfo-10.13-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql10-debuginfo-10.13-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql10-debugsource-10.13-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql10-devel-10.13-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql10-devel-debuginfo-10.13-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql10-plperl-10.13-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql10-plperl-debuginfo-10.13-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql10-plpython-10.13-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql10-plpython-debuginfo-10.13-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql10-pltcl-10.13-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql10-pltcl-debuginfo-10.13-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql10-server-10.13-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql10-server-debuginfo-10.13-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql10-test-10.13-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-12.3-lp152.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-contrib-12.3-lp152.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-contrib-debuginfo-12.3-lp152.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-debuginfo-12.3-lp152.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-debugsource-12.3-lp152.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-devel-12.3-lp152.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-devel-debuginfo-12.3-lp152.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-llvmjit-12.3-lp152.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-llvmjit-debuginfo-12.3-lp152.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-plperl-12.3-lp152.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-plperl-debuginfo-12.3-lp152.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-plpython-12.3-lp152.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-plpython-debuginfo-12.3-lp152.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-pltcl-12.3-lp152.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-pltcl-debuginfo-12.3-lp152.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-server-12.3-lp152.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-server-debuginfo-12.3-lp152.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-server-devel-12.3-lp152.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-server-devel-debuginfo-12.3-lp152.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-test-12.3-lp152.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql96-9.6.19-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql96-contrib-9.6.19-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql96-contrib-debuginfo-9.6.19-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql96-debuginfo-9.6.19-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql96-debugsource-9.6.19-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql96-devel-9.6.19-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql96-devel-debuginfo-9.6.19-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql96-plperl-9.6.19-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql96-plperl-debuginfo-9.6.19-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql96-plpython-9.6.19-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql96-plpython-debuginfo-9.6.19-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql96-pltcl-9.6.19-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql96-pltcl-debuginfo-9.6.19-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql96-server-9.6.19-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql96-server-debuginfo-9.6.19-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql96-test-9.6.19-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libecpg6-32bit-12.3-lp152.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libecpg6-32bit-debuginfo-12.3-lp152.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libpq5-32bit-12.3-lp152.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libpq5-32bit-debuginfo-12.3-lp152.3.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"postgresql11-11.9-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"postgresql11-contrib-11.9-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"postgresql11-contrib-debuginfo-11.9-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"postgresql11-debuginfo-11.9-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"postgresql11-debugsource-11.9-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"postgresql11-devel-11.9-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"postgresql11-devel-debuginfo-11.9-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"postgresql11-llvmjit-11.9-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"postgresql11-llvmjit-debuginfo-11.9-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"postgresql11-plperl-11.9-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"postgresql11-plperl-debuginfo-11.9-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"postgresql11-plpython-11.9-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"postgresql11-plpython-debuginfo-11.9-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"postgresql11-pltcl-11.9-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"postgresql11-pltcl-debuginfo-11.9-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"postgresql11-server-11.9-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"postgresql11-server-debuginfo-11.9-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"postgresql11-server-devel-11.9-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"postgresql11-server-devel-debuginfo-11.9-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"postgresql11-test-11.9-lp152.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / postgresql-contrib / postgresql-devel / etc");
}
