#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0254. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119347);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-2035", "CVE-2013-4152", "CVE-2013-4330", "CVE-2014-0003");
  script_bugtraq_id(59876, 61951, 62706, 65902);
  script_xref(name:"RHSA", value:"2014:0254");

  script_name(english:"RHEL 6 : activemq (RHSA-2014:0254)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An updated activemq package that fixes multiple security issues is now
available for Red Hat OpenShift Enterprise 1.2.7.

The Red Hat Security Response Team has rated this update as having
Important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Apache ActiveMQ provides a SOA infrastructure to connect processes
across heterogeneous systems.

A flaw was found in Apache Camel's parsing of the FILE_NAME header. A
remote attacker able to submit messages to a Camel route, which would
write the provided message to a file, could provide expression
language (EL) expressions in the FILE_NAME header, which would be
evaluated on the server. This could lead to arbitrary remote code
execution in the context of the Camel server process. (CVE-2013-4330)

It was found that the Apache Camel XSLT component allowed XSL
stylesheets to call external Java methods. A remote attacker able to
submit messages to a Camel route could use this flaw to perform
arbitrary remote code execution in the context of the Camel server
process. (CVE-2014-0003)

It was discovered that the Spring OXM wrapper did not expose any
property for disabling entity resolution when using the JAXB
unmarshaller. A remote attacker could use this flaw to conduct XML
External Entity (XXE) attacks on websites, and read files in the
context of the user running the application server. The patch for this
flaw disables external entity processing by default, and provides a
configuration directive to re-enable it. (CVE-2013-4152)

The HawtJNI Library class wrote native libraries to a predictable file
name in /tmp/ when the native libraries were bundled in a JAR file,
and no custom library path was specified. A local attacker could
overwrite these native libraries with malicious versions during the
window between when HawtJNI writes them and when they are executed.
(CVE-2013-2035)

The CVE-2013-2035 issue was discovered by Florian Weimer of the Red
Hat Product Security Team, and the CVE-2014-0003 issue was discovered
by David Jorm of the Red Hat Security Response Team.

All users of Red Hat OpenShift Enterprise 1.2.7 are advised to upgrade
to this updated package, which corrects these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2014:0254"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-2035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-4330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-4152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0003"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected activemq and / or activemq-client packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:activemq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:activemq-client");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:0254";
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
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"activemq-5.9.0-4.redhat.610328.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"activemq-client-5.9.0-4.redhat.610328.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "activemq / activemq-client");
  }
}
