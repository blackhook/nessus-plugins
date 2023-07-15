#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0347. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(52628);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2011-1024", "CVE-2011-1025", "CVE-2011-1081");
  script_bugtraq_id(46363);
  script_xref(name:"RHSA", value:"2011:0347");

  script_name(english:"RHEL 6 : openldap (RHSA-2011:0347)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openldap packages that fix three security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

OpenLDAP is an open source suite of LDAP (Lightweight Directory Access
Protocol) applications and development tools.

A flaw was found in the way OpenLDAP handled authentication failures
being passed from an OpenLDAP slave to the master. If OpenLDAP was
configured with a chain overlay and it forwarded authentication
failures, OpenLDAP would bind to the directory as an anonymous user
and return success, rather than return failure on the authenticated
bind. This could allow a user on a system that uses LDAP for
authentication to log into a directory-based account without knowing
the password. (CVE-2011-1024)

It was found that the OpenLDAP back-ndb back end allowed successful
authentication to the root distinguished name (DN) when any string was
provided as a password. A remote user could use this flaw to access an
OpenLDAP directory if they knew the value of the root DN. Note: This
issue only affected OpenLDAP installations using the NDB back-end,
which is only available for Red Hat Enterprise Linux 6 via third-party
software. (CVE-2011-1025)

A flaw was found in the way OpenLDAP handled modify relative
distinguished name (modrdn) requests. A remote, unauthenticated user
could use this flaw to crash an OpenLDAP server via a modrdn request
containing an empty old RDN value. (CVE-2011-1081)

Users of OpenLDAP should upgrade to these updated packages, which
contain backported patches to resolve these issues. After installing
this update, the OpenLDAP daemons will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-1024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-1025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-1081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2011:0347"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-1025");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:compat-openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-servers-sql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/11");
  script_set_attribute(attribute:"generated_plugin", value:"former");
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
  rhsa = "RHSA-2011:0347";
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
  if (rpm_check(release:"RHEL6", reference:"compat-openldap-2.4.19_2.3.43-15.el6_0.2", epoch:0)) flag++;

  if (rpm_check(release:"RHEL6", reference:"openldap-2.4.19-15.el6_0.2", epoch:0)) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openldap-clients-2.4.19-15.el6_0.2", epoch:0)) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openldap-clients-2.4.19-15.el6_0.2", epoch:0)) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openldap-clients-2.4.19-15.el6_0.2", epoch:0)) flag++;

  if (rpm_check(release:"RHEL6", reference:"openldap-debuginfo-2.4.19-15.el6_0.2", epoch:0)) flag++;

  if (rpm_check(release:"RHEL6", reference:"openldap-devel-2.4.19-15.el6_0.2", epoch:0)) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openldap-servers-2.4.19-15.el6_0.2", epoch:0)) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openldap-servers-2.4.19-15.el6_0.2", epoch:0)) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openldap-servers-2.4.19-15.el6_0.2", epoch:0)) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openldap-servers-sql-2.4.19-15.el6_0.2", epoch:0)) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openldap-servers-sql-2.4.19-15.el6_0.2", epoch:0)) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openldap-servers-sql-2.4.19-15.el6_0.2", epoch:0)) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "compat-openldap / openldap / openldap-clients / openldap-debuginfo / etc");
  }
}
