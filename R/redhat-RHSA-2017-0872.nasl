#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0872. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117313);
  script_version("1.5");
  script_cvs_date("Date: 2019/10/24 15:35:42");

  script_cve_id("CVE-2016-8629", "CVE-2016-9589", "CVE-2017-2585");
  script_xref(name:"RHSA", value:"2017:0872");

  script_name(english:"RHEL 6 : Single Sign-On (RHSA-2017:0872)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Red Hat Single Sign-On 7.1 is now available for Red Hat Enterprise
Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat Single Sign-On is a standalone server, based on the Keycloak
project, that provides authentication and standards-based single
sign-on capabilities for web and mobile applications.

This release of Red Hat Single Sign-On 7.1 serves as a replacement for
Red Hat Single Sign-On 7.0, and includes several bug fixes and
enhancements. For further information regarding those, refer to the
Release Notes linked to in the References section.

Security Fix(es) :

* It was found that keycloak did not correctly check permissions when
handling service account user deletion requests sent to the REST
server. An attacker with service account authentication could use this
flaw to bypass normal permissions and delete users in a separate
realm. (CVE-2016-8629)

* It was found that JBoss EAP 7 Header Cache was inefficient. An
attacker could use this flaw to cause a denial of service attack.
(CVE-2016-9589)

* It was found that keycloak's implementation of HMAC verification for
JWS tokens uses a method that runs in non-constant time, potentially
leaving the application vulnerable to timing attacks. (CVE-2017-2585)

Red Hat would like to thank Gabriel Lavoie (Halogen Software) for
reporting CVE-2016-9589 and Richard Kettelerij (Mindloops) for
reporting CVE-2017-2585."
  );
  # https://access.redhat.com/documentation/en-us/red_hat_single_sign-on/7.1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1825fcce"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:0872"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-8629"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-9589"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-2585"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-sso7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-sso7-freemarker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-sso7-javapackages-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-sso7-keycloak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-sso7-keycloak-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-sso7-libunix-dbus-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-sso7-libunix-dbus-java-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-sso7-libunix-dbus-java-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-sso7-liquibase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-sso7-liquibase-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-sso7-python-javapackages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-sso7-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-sso7-twitter4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-sso7-twitter4j-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-sso7-zxing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-sso7-zxing-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-sso7-zxing-javase");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:0872";
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
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rh-sso7-1-2.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rh-sso7-freemarker-2.3.23-1.redhat_2.2.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rh-sso7-javapackages-tools-3.4.1-5.15.3.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rh-sso7-keycloak-2.5.5-2.Final_redhat_1.1.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rh-sso7-keycloak-server-2.5.5-2.Final_redhat_1.1.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rh-sso7-libunix-dbus-java-0.8.0-2.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rh-sso7-libunix-dbus-java-debuginfo-0.8.0-2.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rh-sso7-libunix-dbus-java-devel-0.8.0-2.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rh-sso7-liquibase-3.4.1-2.redhat_2.1.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rh-sso7-liquibase-core-3.4.1-2.redhat_2.1.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rh-sso7-python-javapackages-3.4.1-5.15.3.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rh-sso7-runtime-1-2.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rh-sso7-twitter4j-4.0.4-1.redhat_3.1.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rh-sso7-twitter4j-core-4.0.4-1.redhat_3.1.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rh-sso7-zxing-3.2.1-1.redhat_4.1.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rh-sso7-zxing-core-3.2.1-1.redhat_4.1.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rh-sso7-zxing-javase-3.2.1-1.redhat_4.1.jbcs.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rh-sso7 / rh-sso7-freemarker / rh-sso7-javapackages-tools / etc");
  }
}
