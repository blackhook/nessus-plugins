#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:1001 and 
# CentOS Errata and Security Advisory 2008:1001 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43717);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-4313", "CVE-2008-4315");
  script_xref(name:"RHSA", value:"2008:1001");

  script_name(english:"CentOS 5 : tog-pegasus (CESA-2008:1001)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tog-pegasus packages that fix security issues are now
available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The tog-pegasus packages provide OpenPegasus Web-Based Enterprise
Management (WBEM) services. WBEM is a platform and resource
independent Distributed Management Task Force (DMTF) standard that
defines a common information model and communication protocol for
monitoring and controlling resources.

Red Hat defines additional security enhancements for OpenGroup Pegasus
WBEM services in addition to those defined by the upstream OpenGroup
Pegasus release. For details regarding these enhancements, refer to
the file 'README.RedHat.Security', included in the Red Hat tog-pegasus
package.

After re-basing to version 2.7.0 of the OpenGroup Pegasus code, these
additional security enhancements were no longer being applied. As a
consequence, access to OpenPegasus WBEM services was not restricted to
the dedicated users as described in README.RedHat.Security. An
attacker able to authenticate using a valid user account could use
this flaw to send requests to WBEM services. (CVE-2008-4313)

Note: default SELinux policy prevents tog-pegasus from modifying
system files. This flaw's impact depends on whether or not tog-pegasus
is confined by SELinux, and on any additional CMPI providers installed
and enabled on a particular system.

Failed authentication attempts against the OpenPegasus CIM server were
not logged to the system log as documented in README.RedHat.Security.
An attacker could use this flaw to perform password guessing attacks
against a user account without leaving traces in the system log.
(CVE-2008-4315)

All tog-pegasus users are advised to upgrade to these updated
packages, which contain patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015455.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d6ce68f0"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015456.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7ed1f77a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tog-pegasus packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tog-pegasus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tog-pegasus-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/11/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/26");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"tog-pegasus-2.7.0-2.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tog-pegasus-devel-2.7.0-2.el5_2.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tog-pegasus / tog-pegasus-devel");
}
