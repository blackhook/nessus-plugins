#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:3255. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130417);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/17");

  script_cve_id("CVE-2019-3899");
  script_xref(name:"RHSA", value:"2019:3255");

  script_name(english:"RHEL 7 : heketi (RHSA-2019:3255)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated heketi packages that fix one security issue, multiple bugs,
and adds various enhancements is now available for OpenShift Container
Storage 3.11 Batch 4 Update.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Heketi provides a RESTful management interface that can be used to
manage the life cycle of GlusterFS volumes. With Heketi, cloud
services like OpenStack Manila, Kubernetes, and OpenShift can
dynamically provision GlusterFS volumes with any of the supported
durability types. Heketi will automatically determine the location for
bricks across the cluster, making sure to place bricks and its
replicas across different failure domains. Heketi also supports any
number of GlusterFS clusters, allowing cloud services to provide
network file storage without being limited to a single GlusterFS
cluster.

The following packages have been upgraded to a later upstream version:
heketi (9.0.0). (BZ#1710080)

Security Fix(es) :

* heketi: heketi can be installed using insecure defaults
(CVE-2019-3899)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Bug Fix(es) :

* Previously, it was easy to inadvertently set Heketi up in an
unsecured way which increased the risk of unauthorized users to make
changes to the storage managed by Heketi. The default settings have
changed to require users to configure authentication and to make
disabling authentication unintentionally more difficult. (BZ#1701838)

* Previously, when Heketi executed commands within
OpenShift/Kubernetes pods, the commands were executed without a
timeout specified. Hence, some commands never returned which differed
from the SSH executor which always executes commands with a timeout.
With this update, the commands that are executed in the gluster
containers have a timeout specified. The timeout values are the same
regardless of what connection type is used. (BZ# 1636912)

* Previously, if Heketi managed multiple clusters and it failed to
create volumes on any of the clusters it would return a generic 'No
space' error message. With this update, error messages produced when
heketi manages multiple gluster clusters have been improved. Heketi
now displays specific errors for when the cluster has no nodes or none
of the nodes have usable devices and also reports on each cluster's
error by prefixing cluster errors with the cluster ID. (BZ#1577803)

* Previously, if operation cleanup was requested from the server
simultaneously, the server would try to initiate cleanup for the same
operation twice. This triggered panic in the server. With this update,
the server no longer panics if two operation cleanups are requested at
the same time. (BZ#1702162)

Enhancement(s) :

* When a node is removed or added to a gluster trusted storage pool
using heketi, the existing endpoints do not get updated automatically.
With this update, to update the endpoints after node addition/removal,
users can now execute the following commands: 1. heketi-cli volume
endpoint patch 2. oc patch ep -p (BZ#1660681)

* With this update, Heketi tracks additional metadata associated with
disk devices even if the path of the device changes. The outputs of
some commands have been updated to reflect the additional metadata.
(BZ#1609553)

Users of Heketi are advised to upgrade to these updated packages,
which adds these enhancements and fix these bugs."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:3255"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-3899"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected heketi, heketi-client and / or python-heketi
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:heketi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:heketi-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-heketi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/31");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:3255";
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
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"heketi-9.0.0-7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"heketi-client-9.0.0-7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-heketi-9.0.0-7.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "heketi / heketi-client / python-heketi");
  }
}
