#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:4042. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131529);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-9512",
    "CVE-2019-9514",
    "CVE-2019-9515",
    "CVE-2019-14837",
    "CVE-2019-14838",
    "CVE-2019-14843"
  );
  script_xref(name:"RHSA", value:"2019:4042");
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"RHEL 8 : Red Hat Single Sign-On 7.3.5 (RHSA-2019:4042) (Ping Flood) (Reset Flood) (Settings Flood)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"New Red Hat Single Sign-On 7.3.5 packages are now available for Red
Hat Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat Single Sign-On 7.3 is a standalone server, based on the
Keycloak project, that provides authentication and standards-based
single sign-on capabilities for web and mobile applications.

This release of Red Hat Single Sign-On 7.3.5 on RHEL 8 serves as a
replacement for Red Hat Single Sign-On 7.3.4, and includes bug fixes
and enhancements, which are documented in the Release Notes document
linked to in the References.

Security Fix(es) :

* keycloak: Service accounts reset password flow not using
placeholder.org domain anymore (CVE-2019-14837)

* undertow: HTTP/2: flood using PING frames results in unbounded
memory growth (CVE-2019-9512)

* undertow: HTTP/2: flood using HEADERS frames results in unbounded
memory growth (CVE-2019-9514)

* undertow: HTTP/2: flood using SETTINGS frames results in unbounded
memory growth (CVE-2019-9515)

* wildfly-core: Incorrect privileges for 'Monitor', 'Auditor' and
'Deployer' user by default (CVE-2019-14838)

* wildfly: wildfly-security-manager: security manager authorization
bypass (CVE-2019-14843)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.");
  # https://access.redhat.com/documentation/en-us/red_hat_single_sign-on/7.3/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?93d4a9a3");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:4042");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-9512");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-9514");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-9515");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-14837");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-14838");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-14843");
  script_set_attribute(attribute:"solution", value:
"Update the affected rh-sso7-keycloak and / or rh-sso7-keycloak-server
packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14843");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-14837");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-sso7-keycloak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-sso7-keycloak-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 8.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:4042";
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
  if (rpm_check(release:"RHEL8", reference:"rh-sso7-keycloak-4.8.15-1.Final_redhat_00001.1.el8sso")) flag++;
  if (rpm_check(release:"RHEL8", reference:"rh-sso7-keycloak-server-4.8.15-1.Final_redhat_00001.1.el8sso")) flag++;

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
