#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0270. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(64695);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-5783");
  script_xref(name:"RHSA", value:"2013:0270");

  script_name(english:"RHEL 5 / 6 : jakarta-commons-httpclient (RHSA-2013:0270)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated jakarta-commons-httpclient packages that fix one security
issue are now available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The Jakarta Commons HttpClient component can be used to build
HTTP-aware client applications (such as web browsers and web service
clients).

The Jakarta Commons HttpClient component did not verify that the
server hostname matched the domain name in the subject's Common Name
(CN) or subjectAltName field in X.509 certificates. This could allow a
man-in-the-middle attacker to spoof an SSL server if they had a
certificate that was valid for any domain name. (CVE-2012-5783)

All users of jakarta-commons-httpclient are advised to upgrade to
these updated packages, which correct this issue. Applications using
the Jakarta Commons HttpClient component must be restarted for this
update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2013:0270"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-5783"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-httpclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-httpclient-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-httpclient-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-httpclient-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-httpclient-manual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2013:0270";
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
  if (rpm_exists(rpm:"jakarta-commons-httpclient-3.0-7", release:"RHEL5") && rpm_check(release:"RHEL5", cpu:"i386", reference:"jakarta-commons-httpclient-3.0-7jpp.2")) flag++;

  if (rpm_exists(rpm:"jakarta-commons-httpclient-3.0-7", release:"RHEL5") && rpm_check(release:"RHEL5", cpu:"s390x", reference:"jakarta-commons-httpclient-3.0-7jpp.2")) flag++;

  if (rpm_exists(rpm:"jakarta-commons-httpclient-3.0-7", release:"RHEL5") && rpm_check(release:"RHEL5", cpu:"x86_64", reference:"jakarta-commons-httpclient-3.0-7jpp.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"jakarta-commons-httpclient-debuginfo-3.0-7jpp.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"jakarta-commons-httpclient-debuginfo-3.0-7jpp.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"jakarta-commons-httpclient-debuginfo-3.0-7jpp.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"jakarta-commons-httpclient-demo-3.0-7jpp.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"jakarta-commons-httpclient-demo-3.0-7jpp.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"jakarta-commons-httpclient-demo-3.0-7jpp.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"jakarta-commons-httpclient-javadoc-3.0-7jpp.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"jakarta-commons-httpclient-javadoc-3.0-7jpp.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"jakarta-commons-httpclient-javadoc-3.0-7jpp.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"jakarta-commons-httpclient-manual-3.0-7jpp.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"jakarta-commons-httpclient-manual-3.0-7jpp.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"jakarta-commons-httpclient-manual-3.0-7jpp.2")) flag++;


  if (rpm_exists(rpm:"jakarta-commons-httpclient-3.1-0", release:"RHEL6") && rpm_check(release:"RHEL6", cpu:"i686", reference:"jakarta-commons-httpclient-3.1-0.7.el6_3")) flag++;

  if (rpm_exists(rpm:"jakarta-commons-httpclient-3.1-0", release:"RHEL6") && rpm_check(release:"RHEL6", cpu:"s390x", reference:"jakarta-commons-httpclient-3.1-0.7.el6_3")) flag++;

  if (rpm_exists(rpm:"jakarta-commons-httpclient-3.1-0", release:"RHEL6") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jakarta-commons-httpclient-3.1-0.7.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jakarta-commons-httpclient-debuginfo-3.1-0.7.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"jakarta-commons-httpclient-debuginfo-3.1-0.7.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jakarta-commons-httpclient-debuginfo-3.1-0.7.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jakarta-commons-httpclient-demo-3.1-0.7.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"jakarta-commons-httpclient-demo-3.1-0.7.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jakarta-commons-httpclient-demo-3.1-0.7.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jakarta-commons-httpclient-javadoc-3.1-0.7.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"jakarta-commons-httpclient-javadoc-3.1-0.7.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jakarta-commons-httpclient-javadoc-3.1-0.7.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jakarta-commons-httpclient-manual-3.1-0.7.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"jakarta-commons-httpclient-manual-3.1-0.7.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jakarta-commons-httpclient-manual-3.1-0.7.el6_3")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jakarta-commons-httpclient / jakarta-commons-httpclient-debuginfo / etc");
  }
}
