#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0423 and 
# CentOS Errata and Security Advisory 2010:0423 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(46694);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-1321");
  script_bugtraq_id(40235);
  script_xref(name:"RHSA", value:"2010:0423");

  script_name(english:"CentOS 3 / 4 / 5 : krb5 (CESA-2010:0423)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated krb5 packages that fix one security issue are now available
for Red Hat Enterprise Linux 3, 4, and 5.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

Kerberos is a network authentication system which allows clients and
servers to authenticate to each other using symmetric encryption and a
trusted third party, the Key Distribution Center (KDC).

A NULL pointer dereference flaw was discovered in the MIT Kerberos
Generic Security Service Application Program Interface (GSS-API)
library. A remote, authenticated attacker could use this flaw to crash
any server application using the GSS-API authentication mechanism, by
sending a specially crafted GSS-API token with a missing checksum
field. (CVE-2010-1321)

Red Hat would like to thank the MIT Kerberos Team for responsibly
reporting this issue. Upstream acknowledges Shawn Emery of Oracle as
the original reporter.

All krb5 users should upgrade to these updated packages, which contain
a backported patch to correct this issue. All running services using
the MIT Kerberos libraries must be restarted for the update to take
effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-June/016711.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?71282979"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-June/016712.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5479f784"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-May/016639.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0e3ee91d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-May/016641.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4a3b57ed"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-May/016643.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0ee6fc14"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-May/016644.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?52c1f3d5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected krb5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"krb5-devel-1.2.7-72")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"krb5-devel-1.2.7-72")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"krb5-libs-1.2.7-72")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"krb5-libs-1.2.7-72")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"krb5-server-1.2.7-72")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"krb5-server-1.2.7-72")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"krb5-workstation-1.2.7-72")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"krb5-workstation-1.2.7-72")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"krb5-devel-1.3.4-62.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"krb5-devel-1.3.4-62.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"krb5-libs-1.3.4-62.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"krb5-libs-1.3.4-62.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"krb5-server-1.3.4-62.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"krb5-server-1.3.4-62.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"krb5-workstation-1.3.4-62.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"krb5-workstation-1.3.4-62.el4_8.2")) flag++;

if (rpm_check(release:"CentOS-5", reference:"krb5-devel-1.6.1-36.el5_5.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"krb5-libs-1.6.1-36.el5_5.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"krb5-server-1.6.1-36.el5_5.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"krb5-workstation-1.6.1-36.el5_5.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-devel / krb5-libs / krb5-server / krb5-workstation");
}
