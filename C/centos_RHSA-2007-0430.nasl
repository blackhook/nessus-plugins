#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0430 and 
# CentOS Errata and Security Advisory 2007:0430 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25496);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-4600");
  script_xref(name:"RHSA", value:"2007:0430");

  script_name(english:"CentOS 3 : openldap (CESA-2007:0430)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A updated openldap packages that fix a security flaw and a memory leak
bug are now available for Red Hat Enterprise Linux 3.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

OpenLDAP is an open source suite of LDAP (Lightweight Directory Access
Protocol) applications, libraries and development tools.

A flaw was found in the way OpenLDAP handled selfwrite access. Users
with selfwrite access were able to modify the distinguished name of
any user. Users with selfwrite access should only be able to modify
their own distinguished name. (CVE-2006-4600)

A memory leak bug was found in OpenLDAP's ldap_start_tls_s() function.
An application using this function could result in an Out Of Memory
(OOM) condition, crashing the application.

All users are advised to upgrade to this updated openldap package,
which contains a backported fix and is not vulnerable to these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013898.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dc9a3794"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013910.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2c090bf3"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013911.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?14da1253"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openldap packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-servers");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/14");
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
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"openldap-2.0.27-23")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openldap-clients-2.0.27-23")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openldap-devel-2.0.27-23")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openldap-servers-2.0.27-23")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openldap / openldap-clients / openldap-devel / openldap-servers");
}
