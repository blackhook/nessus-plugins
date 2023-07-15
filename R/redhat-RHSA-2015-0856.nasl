#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0856. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82908);
  script_version("1.13");
  script_cvs_date("Date: 2020/02/03");

  script_cve_id("CVE-2014-8161", "CVE-2015-0241", "CVE-2015-0243", "CVE-2015-0244");
  script_xref(name:"RHSA", value:"2015:0856");

  script_name(english:"RHEL 6 : postgresql92-postgresql (RHSA-2015:0856)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated postgresql packages that fix multiple security issues are now
available for Red Hat Satellite 5.7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

PostgreSQL is an advanced object-relational database management system
(DBMS).

An information leak flaw was found in the way the PostgreSQL database
server handled certain error messages. An authenticated database user
could possibly obtain the results of a query they did not have
privileges to execute by observing the constraint violation error
messages produced when the query was executed. (CVE-2014-8161)

A buffer overflow flaw was found in the way PostgreSQL handled certain
numeric formatting. An authenticated database user could use a
specially crafted timestamp formatting template to cause PostgreSQL to
crash or, under certain conditions, execute arbitrary code with the
permissions of the user running PostgreSQL. (CVE-2015-0241)

A stack-buffer overflow flaw was found in PostgreSQL's pgcrypto
module. An authenticated database user could use this flaw to cause
PostgreSQL to crash or, potentially, execute arbitrary code with the
permissions of the user running PostgreSQL. (CVE-2015-0243)

A flaw was found in the way PostgreSQL handled certain errors that
were generated during protocol synchronization. An authenticated
database user could use this flaw to inject queries into an existing
connection. (CVE-2015-0244)

Red Hat would like to thank the PostgreSQL project for reporting these
issues. Upstream acknowledges Stephen Frost as the original reporter
of CVE-2014-8161; Andres Freund, Peter Geoghegan, Bernd Helmle, and
Noah Misch as the original reporters of CVE-2015-0241; Marko Tiikkaja
as the original reporter of CVE-2015-0243; and Emil Lenngren as the
original reporter of CVE-2015-0244.

All PostgreSQL users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. If the
postgresql service is running, it will be automatically restarted
after installing this update."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2015:0856"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-0244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-8161"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-0241"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-0243"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql92-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql92-postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql92-postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql92-postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql92-postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql92-postgresql-upgrade");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:0856";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql92-postgresql-9.2.10-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql92-postgresql-9.2.10-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql92-postgresql-contrib-9.2.10-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql92-postgresql-contrib-9.2.10-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql92-postgresql-libs-9.2.10-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql92-postgresql-libs-9.2.10-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql92-postgresql-pltcl-9.2.10-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql92-postgresql-pltcl-9.2.10-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql92-postgresql-server-9.2.10-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql92-postgresql-server-9.2.10-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql92-postgresql-upgrade-9.2.10-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql92-postgresql-upgrade-9.2.10-2.el6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql92-postgresql / postgresql92-postgresql-contrib / etc");
  }
}
