#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1379. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56552);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2011-1527", "CVE-2011-1528", "CVE-2011-1529");
  script_bugtraq_id(50273);
  script_xref(name:"RHSA", value:"2011:1379");

  script_name(english:"RHEL 6 : krb5 (RHSA-2011:1379)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated krb5 packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Kerberos is a network authentication system which allows clients and
servers to authenticate to each other using symmetric encryption and a
trusted third-party, the Key Distribution Center (KDC).

Multiple NULL pointer dereference and assertion failure flaws were
found in the MIT Kerberos KDC when it was configured to use an LDAP
(Lightweight Directory Access Protocol) or Berkeley Database (Berkeley
DB) back end. A remote attacker could use these flaws to crash the
KDC. (CVE-2011-1527, CVE-2011-1528, CVE-2011-1529)

Red Hat would like to thank the MIT Kerberos project for reporting the
CVE-2011-1527 issue. Upstream acknowledges Andrej Ota as the original
reporter of CVE-2011-1527.

All krb5 users should upgrade to these updated packages, which contain
a backported patch to correct these issues. After installing the
updated packages, the krb5kdc daemon will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-1527"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-1528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-1529"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2011-006.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2011:1379"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-pkinit-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-server-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2011:1379";
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
  if (rpm_check(release:"RHEL6", reference:"krb5-debuginfo-1.9-9.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", reference:"krb5-devel-1.9-9.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", reference:"krb5-libs-1.9-9.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"krb5-pkinit-openssl-1.9-9.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"krb5-pkinit-openssl-1.9-9.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"krb5-pkinit-openssl-1.9-9.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"krb5-server-1.9-9.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"krb5-server-1.9-9.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"krb5-server-1.9-9.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", reference:"krb5-server-ldap-1.9-9.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"krb5-workstation-1.9-9.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"krb5-workstation-1.9-9.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"krb5-workstation-1.9-9.el6_1.2")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-debuginfo / krb5-devel / krb5-libs / krb5-pkinit-openssl / etc");
  }
}
