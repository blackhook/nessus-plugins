#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0220. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119431);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-5658", "CVE-2012-6072", "CVE-2012-6073", "CVE-2012-6074", "CVE-2012-6496", "CVE-2013-0158", "CVE-2013-0164");
  script_bugtraq_id(58168, 58169);
  script_xref(name:"RHSA", value:"2013:0220");

  script_name(english:"RHEL 6 : openshift (RHSA-2013:0220)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Red Hat OpenShift Enterprise 1.1 is now available.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Red Hat OpenShift Enterprise is a cloud computing
Platform-as-a-Service (PaaS) solution designed for on-premise or
private cloud deployments.

Refer to the Red Hat OpenShift Enterprise 1.1 Release Notes for
information about the changes in this release. The Release Notes will
be available shortly from https://access.redhat.com/knowledge/docs/

This update also fixes the following security issues :

It was found that the master cryptographic key of Jenkins could be
retrieved via the HTTP server that is hosting Jenkins. A remote
attacker could use this flaw to access the server and execute
arbitrary code with the privileges of the user running Jenkins. Note
that this issue only affected Jenkins instances that had slaves
attached and that also allowed anonymous read access (not the default
configuration). Manual action is also required to correct this issue.
Refer to 'Jenkins Security Advisory 2013-01-04', linked to in the
References, for further information. (CVE-2013-0158)

When the rhc-chk script was run in debug mode, its output included
sensitive information, such as database passwords, in plain text. As
this script is commonly used when troubleshooting, this flaw could
lead to users unintentionally exposing sensitive information in
support channels (for example, a Bugzilla report). This update removes
the rhc-chk script. (CVE-2012-5658)

Multiple flaws in the Jenkins web interface could allow a remote
attacker to perform HTTP response splitting and cross-site scripting
(XSS) attacks, as well as redirecting a victim to an arbitrary page by
utilizing an open redirect flaw. (CVE-2012-6072, CVE-2012-6074,
CVE-2012-6073)

A flaw was found in the way rubygem-activerecord dynamic finders
extracted options from method parameters. A remote attacker could
possibly use this flaw to perform SQL injection attacks against
applications using the Active Record dynamic finder methods.
(CVE-2012-6496)

The openshift-port-proxy-cfg program created a temporary file in an
insecure way. A local attacker could use this flaw to perform a
symbolic link attack, overwriting an arbitrary file accessible to the
root user with a '0' or a '1', which could lead to a denial of
service. By default, OpenShift uses polyinstantiation (per user) for
the /tmp/ directory, minimizing the risk of exploitation by local
attackers. (CVE-2013-0164)

The CVE-2013-0164 issue was discovered by Michael Scherer of the Red
Hat Regional IT team.

Users of Red Hat OpenShift Enterprise 1.0 are advised to upgrade to
Red Hat OpenShift Enterprise 1.1."
  );
  # https://wiki.jenkins-ci.org/display/SECURITY/
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.jenkins.io/display/SECURITY/"
  );
  # https://access.redhat.com/knowledge/docs/
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/documentation/en-us/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2013:0220"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-6496"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-5658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-0158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-0164"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-6073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-6072"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-6074"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libmongodb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mongodb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mongodb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mongodb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mongodb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-broker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-broker-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-haproxy-1.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-ruby-1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-ruby-1.9-scl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-msg-node-mcollective");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-node-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-port-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-mod_passenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-activerecord");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-activerecord-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-passenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-passenger-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-passenger-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-passenger-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-passenger-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-passenger-native-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-activerecord");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-auth-remote-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-console-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-controller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-dns-bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-msg-broker-mcollective");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-node");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/06");
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
  rhsa = "RHSA-2013:0220";
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
  if (rpm_check(release:"RHEL6", reference:"jenkins-1.498-1.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libmongodb-2.0.2-6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mongodb-2.0.2-6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mongodb-debuginfo-2.0.2-6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mongodb-devel-2.0.2-6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mongodb-server-2.0.2-6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-console-0.0.13-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-broker-1.0.10-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-broker-util-1.0.14-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-haproxy-1.4-1.0.3-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-ruby-1.8-1.0.5-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-ruby-1.9-scl-1.0.5-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-msg-node-mcollective-1.0.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-node-util-1.0.7-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-port-proxy-1.0.3-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhc-1.3.2-1.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-mod_passenger-3.0.12-21.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-activerecord-3.2.8-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-activerecord-doc-3.2.8-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-passenger-3.0.12-21.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-passenger-debuginfo-3.0.12-21.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-passenger-devel-3.0.12-21.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-passenger-doc-3.0.12-21.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-passenger-native-3.0.12-21.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-passenger-native-libs-3.0.12-21.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-activerecord-3.0.13-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-auth-remote-user-1.0.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-common-1.0.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-console-1.0.6-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-console-doc-1.0.6-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-controller-1.0.11-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-dns-bind-1.0.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-msg-broker-mcollective-1.0.4-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-node-1.0.10-6.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jenkins / libmongodb / mongodb / mongodb-debuginfo / mongodb-devel / etc");
  }
}
