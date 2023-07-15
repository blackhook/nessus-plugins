#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2915. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119386);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/11");

  script_cve_id("CVE-2016-8651");
  script_xref(name:"RHSA", value:"2016:2915");

  script_name(english:"RHEL 7 : atomic-openshift (RHSA-2016:2915)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An update for atomic-openshift is now available for Red Hat OpenShift
Container Platform 3.1, 3.2, and 3.3.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat OpenShift Container Platform is the company's cloud computing
Platform-as-a-Service (PaaS) solution designed for on-premise or
private cloud deployments.

This advisory contains the RPM packages for Red Hat OpenShift
Container Platform releases 3.3.1.7, 3.2.1.21, and 3.1.1.10. See the
following advisory for the container images for these releases :

https://access.redhat.com/errata/RHBA-2016:2916

Security Fix(es) :

* An input validation flaw was found in the way OpenShift handles
requests for images. A user, with a copy of the manifest associated
with an image, can pull an image even if they do not have access to
the image normally, resulting in the disclosure of any information
contained within the image. (CVE-2016-8651)

Bug Fix(es) for OpenShift Container Platform 3.3 :

* Previously when rapidly updating multiple namespaces controlled by a
single ClusterResourceQuota, the status.total.used can get out of sync
with the sum of the status.namespaces[*].used. This bug fix ensures
the ClusterResourceQuota objects are properly updated. (BZ#1400200)

* When using the `oc new-app --search` command in an environment where
OpenShift Container Platform (OCP) could not reach Docker Hub, the
command failed for any query. OCP now prints a warning and continues
with what was found in other sources. (BZ#1388524)

* The OpenShift Container Platform node daemon did not recover
properly from restarts, and it lost information about attached and
mounted volumes. In rare cases, the daemon deleted all data on a
mounted volume, thinking that it has been already unmounted while it
was only missing its node's cache. This bug fix ensures node caches
are recovered after restarts, and as a result no data loss occurs on
the mounted volumes. (BZ#1398417)

* Previously, ScheduledJobs were not cleaned up on project deletion.
If a new project was created with the same project name, the
previously-defined ScheduledJobs would re-appear. This bug fix ensures
ScheduledJobs are removed when a project is removed. (BZ#1399700)

Bug Fix(es) for OpenShift Container Platform 3.2 :

* When using the `oc new-app --search` command in an environment where
OpenShift Container Platform (OCP) could not reach Docker Hub, the
command failed for any query. OCP now prints a warning and continues
with what was found in other sources. (BZ#1388522)

All OpenShift Container Platform users are advised to upgrade to these
updated packages and images."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2016:2915"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-8651"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-recycle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-sdn-ovs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tuned-profiles-atomic-openshift-node");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/07");
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
  rhsa = "RHSA-2016:2915";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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
  if (rpm_exists(rpm:"atomic-openshift-3.3", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-3.3.1.7-1.git.0.0988966.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-clients-3.3", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-clients-3.3.1.7-1.git.0.0988966.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-clients-redistributable-3.3", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-clients-redistributable-3.3.1.7-1.git.0.0988966.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-docker-excluder-3.3", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"atomic-openshift-docker-excluder-3.3.1.7-1.git.0.0988966.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-dockerregistry-3.3", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-dockerregistry-3.3.1.7-1.git.0.0988966.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-excluder-3.3", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"atomic-openshift-excluder-3.3.1.7-1.git.0.0988966.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-master-3.3", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-master-3.3.1.7-1.git.0.0988966.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-node-3.3", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-node-3.3.1.7-1.git.0.0988966.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-pod-3.3", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-pod-3.3.1.7-1.git.0.0988966.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-recycle-3.1", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-recycle-3.1.1.10-1.git.0.efeef8d.el7aos")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-sdn-ovs-3.3", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-sdn-ovs-3.3.1.7-1.git.0.0988966.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-tests-3.3", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-tests-3.3.1.7-1.git.0.0988966.el7")) flag++;
  if (rpm_exists(rpm:"tuned-profiles-atomic-openshift-node-3.3", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tuned-profiles-atomic-openshift-node-3.3.1.7-1.git.0.0988966.el7")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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
