#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1759. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101786);
  script_version("3.15");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2017-10978", "CVE-2017-10979", "CVE-2017-10980", "CVE-2017-10981", "CVE-2017-10982", "CVE-2017-10983");
  script_xref(name:"RHSA", value:"2017:1759");

  script_name(english:"RHEL 6 : freeradius (RHSA-2017:1759)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for freeradius is now available for Red Hat Enterprise Linux
6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

FreeRADIUS is a high-performance and highly configurable free Remote
Authentication Dial In User Service (RADIUS) server, designed to allow
centralized authentication and authorization for a network.

Security Fix(es) :

* An out-of-bounds write flaw was found in the way FreeRADIUS server
handled certain attributes in request packets. A remote attacker could
use this flaw to crash the FreeRADIUS server or to execute arbitrary
code in the context of the FreeRADIUS server process by sending a
specially crafted request packet. (CVE-2017-10979)

* An out-of-bounds read and write flaw was found in the way FreeRADIUS
server handled RADIUS packets. A remote attacker could use this flaw
to crash the FreeRADIUS server by sending a specially crafted RADIUS
packet. (CVE-2017-10978)

* Multiple memory leak flaws were found in the way FreeRADIUS server
handled decoding of DHCP packets. A remote attacker could use these
flaws to cause the FreeRADIUS server to consume an increasing amount
of memory resources over time, possibly leading to a crash due to
memory exhaustion, by sending specially crafted DHCP packets.
(CVE-2017-10980, CVE-2017-10981)

* Multiple out-of-bounds read flaws were found in the way FreeRADIUS
server handled decoding of DHCP packets. A remote attacker could use
these flaws to crash the FreeRADIUS server by sending a specially
crafted DHCP request. (CVE-2017-10982, CVE-2017-10983)

Red Hat would like to thank the FreeRADIUS project for reporting these
issues. Upstream acknowledges Guido Vranken as the original reporter
of these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:1759"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-10978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-10979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-10980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-10981"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-10982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-10983"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/18");
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
  rhsa = "RHSA-2017:1759";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"freeradius-2.2.6-7.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"freeradius-2.2.6-7.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"freeradius-2.2.6-7.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"freeradius-debuginfo-2.2.6-7.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"freeradius-debuginfo-2.2.6-7.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"freeradius-debuginfo-2.2.6-7.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"freeradius-krb5-2.2.6-7.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"freeradius-krb5-2.2.6-7.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"freeradius-krb5-2.2.6-7.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"freeradius-ldap-2.2.6-7.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"freeradius-ldap-2.2.6-7.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"freeradius-ldap-2.2.6-7.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"freeradius-mysql-2.2.6-7.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"freeradius-mysql-2.2.6-7.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"freeradius-mysql-2.2.6-7.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"freeradius-perl-2.2.6-7.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"freeradius-perl-2.2.6-7.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"freeradius-perl-2.2.6-7.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"freeradius-postgresql-2.2.6-7.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"freeradius-postgresql-2.2.6-7.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"freeradius-postgresql-2.2.6-7.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"freeradius-python-2.2.6-7.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"freeradius-python-2.2.6-7.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"freeradius-python-2.2.6-7.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"freeradius-unixODBC-2.2.6-7.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"freeradius-unixODBC-2.2.6-7.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"freeradius-unixODBC-2.2.6-7.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"freeradius-utils-2.2.6-7.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"freeradius-utils-2.2.6-7.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"freeradius-utils-2.2.6-7.el6_9")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freeradius / freeradius-debuginfo / freeradius-krb5 / etc");
  }
}
