#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update postgresql-2472.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(47727);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2010-0733", "CVE-2010-1169", "CVE-2010-1170", "CVE-2010-1975");

  script_name(english:"openSUSE Security Update : postgresql (openSUSE-SU-2010:0371-1)");
  script_summary(english:"Check for the postgresql-2472 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of postgresql was pblished to fix several minor security
vulnerabilities :

  - CVE-2010-1975: postgresql does not properly check
    privileges during certain RESET ALL operations, which
    allows remote authenticated users to remove arbitrary
    parameter settings.

  - CVE-2010-1170: The PL/Tcl implementation in postgresql
    loads Tcl code from the pltcl_modules table regardless
    of the table's ownership and permissions, which allows
    remote authenticated users, with database-creation
    privileges, to execute arbitrary Tcl code.

  - CVE-2010-1169: Postgresql does not properly restrict
    PL/perl procedures, which allows remote authenticated
    users, with database-creation privileges, to execute
    arbitrary Perl code via a crafted script.

  - CVE-2010-0733: An integer overflow in postgresql allows
    remote authenticated users to crash the daemon via a
    SELECT statement."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=588996"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=605845"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=605926"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=607778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2010-07/msg00010.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE11\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.0", reference:"postgresql-8.3.11-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"postgresql-contrib-8.3.11-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"postgresql-devel-8.3.11-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"postgresql-libs-8.3.11-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"postgresql-plperl-8.3.11-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"postgresql-plpython-8.3.11-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"postgresql-pltcl-8.3.11-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"postgresql-server-8.3.11-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"postgresql-libs-32bit-8.3.11-0.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql");
}
