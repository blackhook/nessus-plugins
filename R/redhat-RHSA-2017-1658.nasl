#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1658. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101141);
  script_version("3.9");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2016-2177", "CVE-2016-2178", "CVE-2016-6304", "CVE-2016-8610");
  script_xref(name:"RHSA", value:"2017:1658");

  script_name(english:"RHEL 6 / 7 : JBoss EAP (RHSA-2017:1658)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update is now available for Red Hat JBoss Enterprise Application
Platform 6.4 for Red Hat Enterprise Linux 6 and Red Hat JBoss
Enterprise Application Platform 6.4 for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat JBoss Enterprise Application Platform is a platform for Java
applications based on the JBoss Application Server.

This release includes bug fixes as well as a new release of OpenSSL.
For further information, see the knowledge base article linked to in
the References section. All users of Red Hat JBoss Enterprise
Application Platform 6.4 on Red Hat Enterprise Linux 7 are advised to
upgrade to these updated packages. The JBoss server process must be
restarted for the update to take effect.

Security Fix(es) :

* A memory leak flaw was found in the way OpenSSL handled TLS status
request extension data during session renegotiation. A remote attacker
could cause a TLS server using OpenSSL to consume an excessive amount
of memory and, possibly, exit unexpectedly after exhausting all
available memory, if it enabled OCSP stapling support. (CVE-2016-6304)

* It was discovered that OpenSSL did not always use constant time
operations when computing Digital Signature Algorithm (DSA)
signatures. A local attacker could possibly use this flaw to obtain a
private DSA key belonging to another user or service running on the
same system. (CVE-2016-2178)

* A denial of service flaw was found in the way the TLS/SSL protocol
defined processing of ALERT packets during a connection handshake. A
remote attacker could use this flaw to make a TLS/SSL server consume
an excessive amount of CPU and fail to accept connections form other
clients. (CVE-2016-8610)

* Multiple integer overflow flaws were found in the way OpenSSL
performed pointer arithmetic. A remote attacker could possibly use
these flaws to cause a TLS/SSL server or client using OpenSSL to
crash. (CVE-2016-2177)

Red Hat would like to thank the OpenSSL project for reporting
CVE-2016-6304 and Shi Lei (Gear Team of Qihoo 360 Inc.) for reporting
CVE-2016-8610. Upstream acknowledges Shi Lei (Gear Team of Qihoo 360
Inc.) as the original reporter of CVE-2016-6304."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/articles/2688611"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/solutions/222023"
  );
  # https://access.redhat.com/documentation/en/
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/documentation/en-us/"
  );
  # https://access.redhat.com/jbossnetwork/restricted/listSoftware.html?product
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?651b7563"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:1658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-2177"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-2178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-6304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-8610"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/30");
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
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:1658";
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

  if (! (rpm_exists(release:"RHEL6", rpm:"jbossas-welcome-content-eap") || rpm_exists(release:"RHEL7", rpm:"jbossas-welcome-content-eap"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-openssl-1.0.2h-13.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-openssl-1.0.2h-13.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-openssl-debuginfo-1.0.2h-13.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-openssl-debuginfo-1.0.2h-13.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-openssl-devel-1.0.2h-13.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-openssl-devel-1.0.2h-13.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-openssl-libs-1.0.2h-13.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-openssl-libs-1.0.2h-13.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-openssl-perl-1.0.2h-13.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-openssl-perl-1.0.2h-13.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jbcs-httpd24-openssl-static-1.0.2h-13.jbcs.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbcs-httpd24-openssl-static-1.0.2h-13.jbcs.el6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-openssl-1.0.2h-13.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-openssl-debuginfo-1.0.2h-13.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-openssl-devel-1.0.2h-13.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-openssl-libs-1.0.2h-13.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-openssl-perl-1.0.2h-13.jbcs.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jbcs-httpd24-openssl-static-1.0.2h-13.jbcs.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jbcs-httpd24-openssl / jbcs-httpd24-openssl-debuginfo / etc");
  }
}
