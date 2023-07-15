#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2666. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119366);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/11");

  script_cve_id("CVE-2015-3281");
  script_xref(name:"RHSA", value:"2015:2666");

  script_name(english:"RHEL 6 : Red Hat OpenShift Enterprise 2.2.8 (RHSA-2015:2666)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Red Hat OpenShift Enterprise release 2.2.8, which fixes one security
issue, several bugs, and introduces feature enhancements, is now
available.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

OpenShift Enterprise by Red Hat is the company's cloud computing
Platform-as-a-Service (PaaS) solution designed for on-premise or
private cloud deployments.

The following security issue is addressed with this release :

An implementation error related to the memory management of request
and responses was found within HAProxy's buffer_slow_realign()
function. An unauthenticated remote attacker could use this flaw to
leak certain memory buffer contents from a past request or session.
(CVE-2015-3281)

Space precludes documenting all of the bug fixes in this advisory. See
the OpenShift Enterprise Technical Notes, which will be updated
shortly for release 2.2.8, for details about these changes :

https://access.redhat.com/documentation/en-US/OpenShift_Enterprise/2/
html-single/Technical_Notes/index.html

All OpenShift Enterprise 2 users are advised to upgrade to these
updated packages."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2015:2666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-3281"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:haproxy15side");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:haproxy15side-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-enterprise-release");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-enterprise-upgrade-broker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-enterprise-upgrade-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-enterprise-yum-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-broker-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-haproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-jbosseap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-jbossews");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-node-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-controller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-routing-daemon");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2015:2666";
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
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"haproxy15side-1.5.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"haproxy15side-debuginfo-1.5.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-enterprise-release-2.2.8-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-enterprise-upgrade-broker-2.2.8-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-enterprise-upgrade-node-2.2.8-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-enterprise-yum-validator-2.2.8-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-broker-util-1.37.4.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-haproxy-1.31.4.1-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-jbosseap-2.27.3.1-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-jbossews-1.35.3.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-python-1.34.1.1-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-node-util-1.38.5.1-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhc-1.38.4.5-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-common-1.29.4.1-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-controller-1.38.4.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-node-1.38.4.1-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-routing-daemon-0.26.4.4-1.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "haproxy15side / haproxy15side-debuginfo / etc");
  }
}
