#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2904. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103956);
  script_version("3.11");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2014-9970", "CVE-2017-12158", "CVE-2017-12159", "CVE-2017-12160", "CVE-2017-12197");
  script_xref(name:"RHSA", value:"2017:2904");

  script_name(english:"RHEL 6 : rh-sso7-keycloak (RHSA-2017:2904)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for rh-sso7-keycloak is now available for Red Hat Single
Sign-On 7.1 for RHEL 6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat Single Sign-On is a standalone server, based on the Keycloak
project, that provides authentication and standards-based single
sign-on capabilities for web and mobile applications.

This release of Red Hat Single Sign-On 7.1.3 serves as a replacement
for Red Hat Single Sign-On 7.1.2, and includes several bug fixes and
enhancements. For further information, refer to the Release Notes
linked to in the References section.

Security Fix(es) :

* It was found that keycloak would accept a HOST header URL in the
admin console and use it to determine web resource locations. An
attacker could use this flaw against an authenticated user to attain
reflected XSS via a malicious server. (CVE-2017-12158)

* It was found that the cookie used for CSRF prevention in Keycloak
was not unique to each session. An attacker could use this flaw to
gain access to an authenticated user session, leading to possible
information disclosure or further attacks. (CVE-2017-12159)

* It was found that libpam4j did not properly validate user accounts
when authenticating. A user with a valid password for a disabled
account would be able to bypass security restrictions and possibly
access sensitive information. (CVE-2017-12197)

* It was found that Keycloak oauth would permit an authenticated
resource to obtain an access/refresh token pair from the
authentication server, permitting indefinite usage in the case of
permission revocation. An attacker on an already compromised resource
could use this flaw to grant himself continued permissions and
possibly conduct further attacks. (CVE-2017-12160)

Red Hat would like to thank Mykhailo Stadnyk (Playtech) for reporting
CVE-2017-12158; Prapti Mittal for reporting CVE-2017-12159; and Bart
Toersche (Simacan) for reporting CVE-2017-12160. The CVE-2017-12197
issue was discovered by Christian Heimes (Red Hat)."
  );
  # https://access.redhat.com/documentation/en-us/red_hat_single_sign-on/7.1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1825fcce"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:2904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-9970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-12158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-12159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-12160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-12197"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected rh-sso7-keycloak and / or rh-sso7-keycloak-server
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-sso7-keycloak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-sso7-keycloak-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2017:2904";
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
  if (rpm_check(release:"RHEL6", reference:"rh-sso7-keycloak-2.5.14-1.Final_redhat_1.1.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rh-sso7-keycloak-server-2.5.14-1.Final_redhat_1.1.jbcs.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rh-sso7-keycloak / rh-sso7-keycloak-server");
  }
}
