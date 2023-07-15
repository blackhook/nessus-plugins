#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0526 and 
# CentOS Errata and Security Advisory 2006:0526 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21905);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-0591", "CVE-2006-2313", "CVE-2006-2314");
  script_bugtraq_id(18092);
  script_xref(name:"RHSA", value:"2006:0526");

  script_name(english:"CentOS 3 / 4 : postgresql (CESA-2006:0526)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated postgresql packages that fix several security vulnerabilities
are now available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

PostgreSQL is an advanced Object-Relational database management system
(DBMS).

A bug was found in the way PostgreSQL's PQescapeString function
escapes strings when operating in a multibyte character encoding. It
is possible for an attacker to provide an application a carefully
crafted string containing invalidly-encoded characters, which may be
improperly escaped, allowing the attacker to inject malicious SQL.
While this update fixes how PQescapeString operates, the PostgreSQL
server has also been modified to prevent such an attack occurring
through unpatched clients. (CVE-2006-2313, CVE-2006-2314). More
details about this issue are available in the linked PostgreSQL
technical documentation.

An integer signedness bug was found in the way PostgreSQL generated
password salts. The actual salt size is only half the size of the
expected salt, making the process of brute forcing password hashes
slightly easier. This update will not strengthen already existing
passwords, but all newly assigned passwords will have the proper salt
length. (CVE-2006-0591)

Users of PostgreSQL should upgrade to these updated packages
containing PostgreSQL version 7.4.13, which corrects these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-May/012906.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?25da7d4d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-May/012907.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3bce9c62"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-May/012910.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a2810143"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-May/012911.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bd654928"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-May/012925.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3c19efa7"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-May/012926.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?45b7bf81"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-7.3.15-2")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-contrib-7.3.15-2")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-devel-7.3.15-2")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-docs-7.3.15-2")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-jdbc-7.3.15-2")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-libs-7.3.15-2")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-pl-7.3.15-2")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-python-7.3.15-2")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-server-7.3.15-2")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-tcl-7.3.15-2")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-test-7.3.15-2")) flag++;

if (rpm_check(release:"CentOS-4", reference:"postgresql-7.4.13-2.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"postgresql-contrib-7.4.13-2.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"postgresql-devel-7.4.13-2.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"postgresql-docs-7.4.13-2.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"postgresql-jdbc-7.4.13-2.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"postgresql-libs-7.4.13-2.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"postgresql-pl-7.4.13-2.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"postgresql-python-7.4.13-2.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"postgresql-server-7.4.13-2.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"postgresql-tcl-7.4.13-2.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"postgresql-test-7.4.13-2.RHEL4.1")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
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
