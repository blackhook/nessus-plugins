#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:3752. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119415);
  script_version("1.6");
  script_cvs_date("Date: 2019/10/24 15:35:46");

  script_cve_id("CVE-2018-1002105");
  script_xref(name:"RHSA", value:"2018:3752");

  script_name(english:"RHEL 7 : OpenShift Container Platform 3.4 (RHSA-2018:3752)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update is now available for Red Hat OpenShift Container Platform
release 3.4.

Red Hat Product Security has rated this update as having a security
impact of Critical. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat OpenShift Container Platform is Red Hat's cloud computing
Kubernetes application platform solution designed for on-premise or
private cloud deployments.

Security Fix(es) :

* A privilege escalation vulnerability exists in OpenShift Container
Platform 3.x which allows for compromise of pods running on a compute
node to which a pod is scheduled with normal user privilege. This
access could include access to all secrets, pods, environment
variables, running pod/container processes, and persistent volumes,
including in privileged containers. Additionally, on versions 3.6 and
higher of OpenShift Container Platform, this vulnerability allows
cluster-admin level access to any API hosted by an aggregated API
server. This includes the 'servicecatalog' API which is installed
by default in 3.7 and later. Cluster-admin level access to the service
catalog allows creation of brokered services by an unauthenticated
user with escalated privileges in any namespace and on any node. This
could lead to an attacker being allowed to deploy malicious code, or
alter existing services. (CVE-2018-1002105)

This advisory contains the RPM packages for Red Hat OpenShift
Container Platform 3.4. See the following advisory for the container
images for this release :

https://access.redhat.com/errata/RHBA-2018:3751

All OpenShift Container Platform 3.4 users are advised to upgrade to
these updated packages and images."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHBA-2018:0114"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.openshift.com/container-platform/3.4/release_notes/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:3752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-1002105"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-clients-redistributable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-docker-excluder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-dockerregistry");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-excluder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-master");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-pod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-sdn-ovs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible-callback-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible-filter-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible-lookup-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible-playbooks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible-roles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tuned-profiles-atomic-openshift-node");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/04");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2018:3752";
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
  if (rpm_exists(rpm:"atomic-openshift-3.4", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-3.4.1.44.57-1.git.0.a631031.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-clients-3.4", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-clients-3.4.1.44.57-1.git.0.a631031.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-clients-redistributable-3.4", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-clients-redistributable-3.4.1.44.57-1.git.0.a631031.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-docker-excluder-3.4", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"atomic-openshift-docker-excluder-3.4.1.44.57-1.git.0.a631031.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-dockerregistry-3.4", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-dockerregistry-3.4.1.44.57-1.git.0.a631031.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-excluder-3.4", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"atomic-openshift-excluder-3.4.1.44.57-1.git.0.a631031.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-master-3.4", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-master-3.4.1.44.57-1.git.0.a631031.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-node-3.4", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-node-3.4.1.44.57-1.git.0.a631031.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-pod-3.4", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-pod-3.4.1.44.57-1.git.0.a631031.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-sdn-ovs-3.4", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-sdn-ovs-3.4.1.44.57-1.git.0.a631031.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-tests-3.4", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-tests-3.4.1.44.57-1.git.0.a631031.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-utils-3.4", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"atomic-openshift-utils-3.4.172-1.git.0.33fe526.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-3.4", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-3.4.172-1.git.0.33fe526.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-callback-plugins-3.4", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-callback-plugins-3.4.172-1.git.0.33fe526.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-docs-3.4", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-docs-3.4.172-1.git.0.33fe526.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-filter-plugins-3.4", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-filter-plugins-3.4.172-1.git.0.33fe526.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-lookup-plugins-3.4", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-lookup-plugins-3.4.172-1.git.0.33fe526.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-playbooks-3.4", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-playbooks-3.4.172-1.git.0.33fe526.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-roles-3.4", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-roles-3.4.172-1.git.0.33fe526.el7")) flag++;
  if (rpm_exists(rpm:"tuned-profiles-atomic-openshift-node-3.4", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tuned-profiles-atomic-openshift-node-3.4.1.44.57-1.git.0.a631031.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "atomic-openshift / atomic-openshift-clients / etc");
  }
}
