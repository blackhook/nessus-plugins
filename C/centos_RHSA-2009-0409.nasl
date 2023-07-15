#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0409 and 
# CentOS Errata and Security Advisory 2009:0409 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43740);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-0844", "CVE-2009-0845", "CVE-2009-0846", "CVE-2009-0847");
  script_xref(name:"RHSA", value:"2009:0409");

  script_name(english:"CentOS 4 : krb5 (CESA-2009:0409)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated krb5 packages that fix a security issue are now available for
Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Kerberos is a network authentication system which allows clients and
servers to authenticate to each other using symmetric encryption and a
trusted third party, the Key Distribution Center (KDC).

An input validation flaw was found in the ASN.1 (Abstract Syntax
Notation One) decoder used by MIT Kerberos. A remote attacker could
use this flaw to crash a network service using the MIT Kerberos
library, such as kadmind or krb5kdc, by causing it to dereference or
free an uninitialized pointer. (CVE-2009-0846)

All krb5 users should upgrade to these updated packages, which contain
a backported patch to correct this issue. All running services using
the MIT Kerberos libraries must be restarted for the update to take
effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-April/015727.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c28f86d4"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-April/015816.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b3902760"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-April/015817.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6e263e89"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected krb5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"krb5-devel-1.3.4-60.el4_7.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"krb5-devel-1.3.4-60.c4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"krb5-devel-1.3.4-60.el4_7.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"krb5-libs-1.3.4-60.el4_7.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"krb5-libs-1.3.4-60.c4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"krb5-libs-1.3.4-60.el4_7.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"krb5-server-1.3.4-60.el4_7.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"krb5-server-1.3.4-60.c4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"krb5-server-1.3.4-60.el4_7.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"krb5-workstation-1.3.4-60.el4_7.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"krb5-workstation-1.3.4-60.c4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"krb5-workstation-1.3.4-60.el4_7.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-devel / krb5-libs / krb5-server / krb5-workstation");
}
