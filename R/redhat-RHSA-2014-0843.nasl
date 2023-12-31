#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0843. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76401);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-0075", "CVE-2014-0096", "CVE-2014-0099", "CVE-2014-0119");
  script_bugtraq_id(67667, 67668, 67669, 67671);
  script_xref(name:"RHSA", value:"2014:0843");

  script_name(english:"RHEL 5 / 6 : JBoss EAP (RHSA-2014:0843)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Red Hat JBoss Enterprise Application Platform 6.2.4 packages
that fix multiple security issues are now available for Red Hat
Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Red Hat JBoss Enterprise Application Platform 6 is a platform for Java
applications based on JBoss Application Server 7.

It was discovered that JBoss Web did not limit the length of chunk
sizes when using chunked transfer encoding. A remote attacker could
use this flaw to perform a denial of service attack against JBoss Web
by streaming an unlimited quantity of data, leading to excessive
consumption of server resources. (CVE-2014-0075)

It was found that JBoss Web did not check for overflowing values when
parsing request content length headers. A remote attacker could use
this flaw to perform an HTTP request smuggling attack on a JBoss Web
server located behind a reverse proxy that processed the content
length header correctly. (CVE-2014-0099)

It was found that the org.apache.catalina.servlets.DefaultServlet
implementation in JBoss Web allowed the definition of XML External
Entities (XXEs) in provided XSLTs. A malicious application could use
this to circumvent intended security restrictions to disclose
sensitive information. (CVE-2014-0096)

It was found that, in certain circumstances, it was possible for a
malicious web application to replace the XML parsers used by JBoss Web
to process XSLTs for the default servlet, JSP documents, tag library
descriptors (TLDs), and tag plug-in configuration files. The injected
XML parser(s) could then bypass the limits imposed on XML external
entities and/or gain access to the XML files processed for other web
applications deployed on the same JBoss Web instance. (CVE-2014-0119)

The CVE-2014-0075 issue was discovered by David Jorm of Red Hat
Product Security.

All users of Red Hat JBoss Enterprise Application Platform 6.2.4 on
Red Hat Enterprise Linux 5 and 6 are advised to upgrade to these
updated packages. The JBoss server process must be restarted for the
update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2014:0843"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0096"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0099"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0119"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected jbossweb package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:0843";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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

  if (! (rpm_exists(release:"RHEL5", rpm:"jbossas-welcome-content-eap") || rpm_exists(release:"RHEL6", rpm:"jbossas-welcome-content-eap"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

  if (rpm_check(release:"RHEL5", reference:"jbossweb-7.3.2-4.Final_redhat_3.1.ep6.el5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"jbossweb-7.3.2-4.Final_redhat_3.1.ep6.el6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jbossweb");
  }
}
