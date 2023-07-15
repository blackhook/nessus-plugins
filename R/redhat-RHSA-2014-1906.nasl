#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1906. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119357);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-3602", "CVE-2014-3674");
  script_bugtraq_id(71090, 71092);
  script_xref(name:"RHSA", value:"2014:1906");

  script_name(english:"RHEL 6 : Red Hat OpenShift Enterprise 2.1.9 (RHSA-2014:1906)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Red Hat OpenShift Enterprise release 2.1.9, which fixes two security
issues, several bugs, and add one enhancement, is now available.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

OpenShift Enterprise by Red Hat is the company's cloud computing
Platform-as-a-Service (PaaS) solution designed for on-premise or
private cloud deployments.

It was found that OpenShift Enterprise 2.1 did not properly restrict
access to services running on different gears. This could allow an
attacker to access unprotected network resources running in another
user's gear.

In a previous update, OpenShift Enterprise 2.2 introduced the
oo-gear-firewall command, which creates firewall rules and SELinux
policy to contain services running on gears to their own internal gear
IPs. The command is invoked by default during new installations of
OpenShift Enterprise 2.2 to prevent this security issue. This update
backports the command to OpenShift Enterprise 2.1.; administrators
should run the following command on node hosts in existing OpenShift
Enterprise 2.1 deployments after applying this update to address this
security issue :

# oo-gear-firewall -i enable -s enable

Please see the man page of the oo-gear-firewall command for more
details. (CVE-2014-3674)

It was found that OpenShift Enterprise did not restrict access to the
/proc/net/tcp file in gears, which allowed local users to view all
listening connections and connected sockets. This could result in
remote system's IP or port numbers in use to be exposed, which may be
useful for further targeted attacks.

Note that for local listeners, OpenShift Enterprise restricts
connections to within the gear by default, so even with the knowledge
of the local port and IP, the attacker is unable to connect. The
SELinux policy on node hosts has been updated to prevent this gear
information from being accessed by local users.

Due to the closing of this access, JBoss-based cartridges that relied
on it previously must be upgraded according to the standard procedure.
This is a compatible cartridge upgrade and therefore does not require
a restart. (CVE-2014-3602)

Space precludes documenting all of the bug fixes and enhancements in
this advisory. See the OpenShift Enterprise Technical Notes linked to
in the References section, which will be updated shortly for release
2.1.9, for details about these changes.

All OpenShift Enterprise users are advised to upgrade to these updated
packages."
  );
  # https://access.redhat.com/documentation/en-US/OpenShift_Enterprise/2/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1e45a65b"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2014:1906"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-3674"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-3602"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-enterprise-release");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-enterprise-upgrade-broker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-enterprise-upgrade-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-enterprise-yum-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-broker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-broker-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-jbosseap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-jbossews");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-msg-node-mcollective");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-node-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-controller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-frontend-apache-mod-rewrite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-frontend-apache-vhost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-frontend-apachedb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-frontend-haproxy-sni-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-msg-broker-mcollective");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-node");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2014:1906";
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
  if (rpm_check(release:"RHEL6", reference:"openshift-enterprise-release-2.1.9-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-enterprise-upgrade-broker-2.1.9-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-enterprise-upgrade-node-2.1.9-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-enterprise-yum-validator-2.1.9-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-broker-1.16.1.14-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-broker-util-1.23.8.14-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-jbosseap-2.16.3.7-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-jbossews-1.22.3.7-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-msg-node-mcollective-1.22.2.3-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-node-util-1.22.20.5-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-controller-1.23.10.15-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-frontend-apache-mod-rewrite-0.5.2.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-frontend-apache-vhost-0.5.2.6-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-frontend-apachedb-0.4.1.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-frontend-haproxy-sni-proxy-0.3.2.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-msg-broker-mcollective-1.23.3.6-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-node-1.23.9.26-1.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openshift-enterprise-release / openshift-enterprise-upgrade-broker / etc");
  }
}
