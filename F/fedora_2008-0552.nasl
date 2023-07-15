#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-0552.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(29948);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2007-4769", "CVE-2007-4772", "CVE-2007-6067", "CVE-2007-6600", "CVE-2007-6601");
  script_bugtraq_id(27163);
  script_xref(name:"FEDORA", value:"2008-0552");

  script_name(english:"Fedora 7 : postgresql-8.2.6-1.fc7 (2008-0552)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Mon Jan 7 2008 Tom Lane <tgl at redhat.com> 8.2.6-1

    - Update to PostgreSQL 8.2.6 to fix CVE-2007-4769,
      CVE-2007-4772, CVE-2007-6067, CVE-2007-6600,
      CVE-2007-6601

  - Make initscript and pam config files be installed
    unconditionally; seems new buildroots don't necessarily
    have those directories in place

  - Thu Sep 20 2007 Tom Lane <tgl at redhat.com> 8.2.5-1

    - Update to PostgreSQL 8.2.5 and pgtcl 1.6.0

    - Fix multilib problem for /usr/include/ecpg_config.h
      (which is new in 8.2.x)

    - Use tzdata package's data files instead of private
      copy, so that postgresql-server need not be turned for
      routine timezone updates

  - Don't remove postgres user/group during RPM uninstall,
    per Fedora packaging guidelines

  - Recent perl changes in rawhide mean we need a more
    specific BuildRequires

    - Wed Jun 20 2007 Tom Lane <tgl at redhat.com> 8.2.4-2

    - Fix oversight in postgresql-test makefile: pg_regress
      isn't a shell script anymore. Per upstream bug 3398.

  - Tue Apr 24 2007 Tom Lane <tgl at redhat.com> 8.2.4-1

    - Update to PostgreSQL 8.2.4 for CVE-2007-2138, data
      loss bugs Resolves: #237682

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=315231"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=316511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=400931"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=427127"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=427128"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=427772"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-January/006822.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b94a6f53"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189, 264, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 7.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC7", reference:"postgresql-8.2.6-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"postgresql-contrib-8.2.6-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"postgresql-debuginfo-8.2.6-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"postgresql-devel-8.2.6-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"postgresql-docs-8.2.6-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"postgresql-libs-8.2.6-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"postgresql-plperl-8.2.6-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"postgresql-plpython-8.2.6-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"postgresql-pltcl-8.2.6-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"postgresql-python-8.2.6-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"postgresql-server-8.2.6-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"postgresql-tcl-8.2.6-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"postgresql-test-8.2.6-1.fc7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / postgresql-contrib / postgresql-debuginfo / etc");
}