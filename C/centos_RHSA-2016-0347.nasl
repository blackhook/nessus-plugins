#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0347 and 
# CentOS Errata and Security Advisory 2016:0347 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(89088);
  script_version("2.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-0773");
  script_xref(name:"RHSA", value:"2016:0347");

  script_name(english:"CentOS 6 : postgresql (CESA-2016:0347)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated postgresql packages that fix one security issue are now
available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

PostgreSQL is an advanced object-relational database management system
(DBMS).

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the PostgreSQL handling code for regular expressions. A
remote attacker could use a specially crafted regular expression to
cause PostgreSQL to crash or possibly execute arbitrary code.
(CVE-2016-0773)

Red Hat would like to thank PostgreSQL upstream for reporting this
issue. Upstream acknowledges Tom Lane and Greg Stark as the original
reporters.

All PostgreSQL users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. If the
postgresql service is running, it will be automatically restarted
after installing this update."
  );
  # https://lists.centos.org/pipermail/centos-announce/2016-March/021715.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6ce49ff4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0773");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"postgresql-8.4.20-5.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"postgresql-contrib-8.4.20-5.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"postgresql-devel-8.4.20-5.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"postgresql-docs-8.4.20-5.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"postgresql-libs-8.4.20-5.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"postgresql-plperl-8.4.20-5.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"postgresql-plpython-8.4.20-5.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"postgresql-pltcl-8.4.20-5.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"postgresql-server-8.4.20-5.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"postgresql-test-8.4.20-5.el6_7")) flag++;


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
