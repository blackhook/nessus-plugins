#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1094. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119373);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/11");

  script_cve_id("CVE-2016-3703", "CVE-2016-3708", "CVE-2016-3738");
  script_xref(name:"RHSA", value:"2016:1094");

  script_name(english:"RHEL 7 : Red Hat OpenShift Enterprise 3.2 (RHSA-2016:1094)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An update for atomic-openshift and nodejs-node-uuid is now available
for Red Hat OpenShift Enterprise 3.2. In addition, all images have
been rebuilt on the new RHEL 7.2.4 base image.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

OpenShift Enterprise by Red Hat is the company's cloud computing
Platform-as-a-Service (PaaS) solution designed for on-premise or
private cloud deployments.

Security Fix(es) :

* A vulnerability was found in the STI build process in OpenShift
Enterprise. Access to STI builds was not properly restricted, allowing
an attacker to use STI builds to access the Docker socket and escalate
their privileges. (CVE-2016-3738)

* An origin validation vulnerability was found in OpenShift
Enterprise. An attacker could potentially access API credentials
stored in a web browser's localStorage if anonymous access was granted
to a service/proxy or pod/ proxy API for a specific pod, and an
authorized access_token was provided in the query parameter.
(CVE-2016-3703)

* A flaw was found in OpenShift Enterprise when multi-tenant SDN is
enabled and a build is run within a namespace that would normally be
isolated from pods in other namespaces. If an s2i build is run in such
an environment the container being built can access network resources
on pods that should not be available to it. (CVE-2016-3708)

The CVE-2016-3738 issue was discovered by David Eads (Red Hat); the
CVE-2016-3703 issue was discovered by Jordan Liggitt (Red Hat); and
the CVE-2016-3708 issue was discovered by Ben Parees (Red Hat).

This update includes the following images :

openshift3/ose:v3.2.0.44-2 openshift3/ose-deployer:v3.2.0.44-2
openshift3/ose-docker-builder:v3.2.0.44-2
openshift3/ose-docker-registry:v3.2.0.44-2
openshift3/ose-f5-router:v3.2.0.44-2
openshift3/ose-haproxy-router:v3.2.0.44-2
openshift3/ose-keepalived-ipfailover:v3.2.0.44-2
openshift3/ose-pod:v3.2.0.44-2 openshift3/ose-recycler:v3.2.0.44-2
openshift3/ose-sti-builder:v3.2.0.44-2
openshift3/jenkins-1-rhel7:1.642-32
openshift3/logging-auth-proxy:3.2.0-4
openshift3/logging-deployment:3.2.0-9
openshift3/logging-elasticsearch:3.2.0-8
openshift3/logging-fluentd:3.2.0-8 openshift3/logging-kibana:3.2.0-4
openshift3/metrics-deployer:3.2.0-6
openshift3/metrics-heapster:3.2.0-6 openshift3/mongodb-24-rhel7:2.4-28
openshift3/mysql-55-rhel7:5.5-26 openshift3/nodejs-010-rhel7:0.10-35
openshift3/node:v3.2.0.44-2 openshift3/openvswitch:v3.2.0.44-2
openshift3/perl-516-rhel7:5.16-38 openshift3/php-55-rhel7:5.5-35
openshift3/postgresql-92-rhel7:9.2-25
openshift3/python-33-rhel7:3.3-35 openshift3/ruby-20-rhel7:2.0-35

aep3_beta/aep:v3.2.0.44-2 aep3_beta/aep-deployer:v3.2.0.44-2
aep3_beta/aep-docker-registry:v3.2.0.44-2
aep3_beta/aep-f5-router:v3.2.0.44-2
aep3_beta/aep-haproxy-router:v3.2.0.44-2
aep3_beta/aep-keepalived-ipfailover:v3.2.0.44-2
aep3_beta/aep-pod:v3.2.0.44-2 aep3_beta/aep-recycler:v3.2.0.44-2
aep3_beta/logging-auth-proxy:3.2.0-4
aep3_beta/logging-deployment:3.2.0-9
aep3_beta/logging-elasticsearch:3.2.0-8
aep3_beta/logging-fluentd:3.2.0-8 aep3_beta/logging-kibana:3.2.0-4
aep3_beta/metrics-deployer:3.2.0-6 aep3_beta/metrics-heapster:3.2.0-6
aep3_beta/node:v3.2.0.44-2 aep3_beta/openvswitch:v3.2.0.44-2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2016:1094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-3703"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-3708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-3738"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-clients-redistributable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-dockerregistry");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-master");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-pod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-recycle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-sdn-ovs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-node-uuid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tuned-profiles-atomic-openshift-node");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/19");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:1094";
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
  if (rpm_exists(rpm:"atomic-openshift-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-3.2.0.44-1.git.0.a4463d9.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-clients-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-clients-3.2.0.44-1.git.0.a4463d9.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-clients-redistributable-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-clients-redistributable-3.2.0.44-1.git.0.a4463d9.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-dockerregistry-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-dockerregistry-3.2.0.44-1.git.0.a4463d9.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-master-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-master-3.2.0.44-1.git.0.a4463d9.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-node-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-node-3.2.0.44-1.git.0.a4463d9.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-pod-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-pod-3.2.0.44-1.git.0.a4463d9.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-recycle-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-recycle-3.2.0.44-1.git.0.a4463d9.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-sdn-ovs-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-sdn-ovs-3.2.0.44-1.git.0.a4463d9.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-tests-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-tests-3.2.0.44-1.git.0.a4463d9.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-node-uuid-1.4.7-1.el7")) flag++;
  if (rpm_exists(rpm:"tuned-profiles-atomic-openshift-node-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tuned-profiles-atomic-openshift-node-3.2.0.44-1.git.0.a4463d9.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "atomic-openshift / atomic-openshift-clients / etc");
  }
}
