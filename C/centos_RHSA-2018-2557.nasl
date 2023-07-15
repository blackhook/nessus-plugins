#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:2557 and 
# CentOS Errata and Security Advisory 2018:2557 respectively.
#

include("compat.inc");

if (description)
{
  script_id(112163);
  script_version("1.5");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2018-10915");
  script_xref(name:"RHSA", value:"2018:2557");

  script_name(english:"CentOS 7 : postgresql (CESA-2018:2557)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for postgresql is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

PostgreSQL is an advanced object-relational database management system
(DBMS).

The following packages have been upgraded to a later upstream version:
postgresql (9.2.24). (BZ#1612667)

Security Fix(es) :

* postgresql: Certain host connection parameters defeat client-side
security defenses (CVE-2018-10915)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank the PostgreSQL project for reporting this
issue. Upstream acknowledges Andrew Krasichkov as the original
reporter."
  );
  # https://lists.centos.org/pipermail/centos-announce/2018-August/023017.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fa5ea80b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10915");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-upgrade");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"postgresql-9.2.24-1.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"postgresql-contrib-9.2.24-1.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"postgresql-devel-9.2.24-1.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"postgresql-docs-9.2.24-1.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"postgresql-libs-9.2.24-1.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"postgresql-plperl-9.2.24-1.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"postgresql-plpython-9.2.24-1.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"postgresql-pltcl-9.2.24-1.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"postgresql-server-9.2.24-1.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"postgresql-static-9.2.24-1.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"postgresql-test-9.2.24-1.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"postgresql-upgrade-9.2.24-1.el7_5")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / postgresql-contrib / postgresql-devel / etc");
}
