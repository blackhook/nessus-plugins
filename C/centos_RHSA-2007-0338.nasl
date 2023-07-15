#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0338 and 
# CentOS Errata and Security Advisory 2007:0338 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25204);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-2028");
  script_bugtraq_id(23466);
  script_xref(name:"RHSA", value:"2007:0338");

  script_name(english:"CentOS 3 / 4 / 5 : freeradius (CESA-2007:0338)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated freeradius packages that fix a memory leak flaw are now
available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

FreeRADIUS is a high-performance and highly configurable free RADIUS
server designed to allow centralized authentication and authorization
for a network.

A memory leak flaw was found in the way FreeRADIUS parses certain
authentication requests. A remote attacker could send a specially
crafted authentication request which could cause FreeRADIUS to leak a
small amount of memory. If enough of these requests are sent, the
FreeRADIUS daemon would consume a vast quantity of system memory
leading to a possible denial of service. (CVE-2007-2028)

Users of FreeRADIUS should update to these erratum packages, which
contain a backported patch to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013747.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?db9965e2"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013748.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?91b25dc4"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013749.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c837ab82"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013750.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2b49ea54"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013753.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?83fbe728"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013754.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7b824ce2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected freeradius packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius-unixODBC");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"freeradius-1.0.1-2.RHEL3.4")) flag++;
if (rpm_check(release:"CentOS-3", reference:"freeradius-mysql-1.0.1-2.RHEL3.4")) flag++;
if (rpm_check(release:"CentOS-3", reference:"freeradius-postgresql-1.0.1-2.RHEL3.4")) flag++;
if (rpm_check(release:"CentOS-3", reference:"freeradius-unixODBC-1.0.1-2.RHEL3.4")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"freeradius-1.0.1-3.RHEL4.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"freeradius-mysql-1.0.1-3.RHEL4.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"freeradius-postgresql-1.0.1-3.RHEL4.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"freeradius-unixODBC-1.0.1-3.RHEL4.5")) flag++;

if (rpm_check(release:"CentOS-5", reference:"freeradius-1.1.3-1.2.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"freeradius-mysql-1.1.3-1.2.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"freeradius-postgresql-1.1.3-1.2.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"freeradius-unixODBC-1.1.3-1.2.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freeradius / freeradius-mysql / freeradius-postgresql / etc");
}
