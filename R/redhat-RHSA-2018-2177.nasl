#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:2177. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111145);
  script_version("1.6");
  script_cvs_date("Date: 2019/10/24 15:35:45");

  script_cve_id("CVE-2018-10861", "CVE-2018-1128", "CVE-2018-1129");
  script_xref(name:"RHSA", value:"2018:2177");

  script_name(english:"RHEL 7 : Red Hat Ceph Storage 3.0 (RHSA-2018:2177)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for ceph is now available for Red Hat Ceph Storage 3.0 for
Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat Ceph Storage is a scalable, open, software-defined storage
platform that combines the most stable version of the Ceph storage
system with a Ceph management platform, deployment utilities, and
support services.

Security Fix(es) :

* ceph: cephx protocol is vulnerable to replay attack (CVE-2018-1128)

* ceph: cephx uses weak signatures (CVE-2018-1129)

* ceph: ceph-mon does not perform authorization on OSD pool ops
(CVE-2018-10861)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Bug Fix(es) :

* Previously, Ceph RADOS Gateway (RGW) instances in zones configured
for multi-site replication would crash if configured to disable sync
('rgw_run_sync_thread = false'). Therefor, multi-site replication
environments could not start dedicated non-replication RGW instances.
With this update, the 'rgw_run_sync_thread' option can be used to
configure RGW instances that will not participate in replication even
if their zone is replicated. (BZ#1552202)

* Previously, when increasing 'max_mds' from '1' to '2', if the
Metadata Server (MDS) daemon was in the starting/resolve state for a
long period of time, then restarting the MDS daemon lead to assert.
This caused the Ceph File System (CephFS) to be in degraded state.
With this update, increasing 'max_mds' no longer causes CephFS to be
in degraded state. (BZ#1566016)

* Previously, the transition to containerized Ceph left some
'ceph-disk' unit files. The files were harmless, but appeared as
failing. With this update, executing the
'switch-from-non-containerized-to-containerized-ceph-daemons.yml'
playbook disables the 'ceph-disk' unit files too. (BZ#1577846)

* Previously, the 'entries_behind_master' metric output from the 'rbd
mirror image status' CLI tool did not always reduce to zero under
synthetic workloads. This could cause a false alarm that there is an
issue with RBD mirroring replications. With this update, the metric is
now updated periodically without the need for an explicit I/O flush in
the workload. (BZ#1578509)

* Previously, when using the 'pool create' command with
'expected_num_objects', placement group (PG) directories were not
pre-created at pool creation time as expected, resulting in
performance drops when filestore splitting occurred. With this update,
the 'expected_num_objects' parameter is now passed through to
filestore correctly, and PG directories for the expected number of
objects are pre-created at pool creation time. (BZ#1579039)

* Previously, internal RADOS Gateway (RGW) multi-site sync logic
behaved incorrectly when attempting to sync containers with S3 object
versioning enabled. Objects in versioning-enabled containers would
fail to sync in some scenarios--for example, when using 's3cmd sync'
to mirror a filesystem directory. With this update, RGW multi-site
replication logic has been corrected for the known failure cases.
(BZ#1580497)

* When restarting OSD daemons, the 'ceph-ansible' restart script goes
through all the daemons by listing the units with systemctl
list-units. Under certain circumstances, the output of the command
contains extra spaces, which caused parsing and restart to fail. With
this update, the underlying code has been changed to handle the extra
space.

* Previously, the Ceph RADOS Gateway (RGW) server treated negative
byte-range object requests ('bytes=0--1') as invalid. Applications
that expect the AWS behavior for negative or other invalid range
requests saw unexpected errors and could fail. With this update, a new
option 'rgw_ignore_get_invalid_range' has been added to RGW. When
'rgw_ignore_get_invalid_range' is set to 'true', the RGW behavior for
invalid range requests is backwards compatible with AWS."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:2177"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-1128"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-1129"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-10861"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-radosgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cephmetrics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cephmetrics-ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cephmetrics-collectors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cephmetrics-grafana-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcephfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcephfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librados-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librados2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libradosstriper1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librbd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librgw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librgw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nfs-ganesha");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nfs-ganesha-ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nfs-ganesha-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nfs-ganesha-rgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-rgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rbd-mirror");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/18");
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
  rhsa = "RHSA-2018:2177";
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

  if (! (rpm_exists(release:"RHEL7", rpm:"librados2-12.*\.el7cp"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Ceph Storage");

  if (rpm_check(release:"RHEL7", reference:"ceph-ansible-3.0.39-1.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-base-12.2.4-30.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-common-12.2.4-30.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-debuginfo-12.2.4-30.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-fuse-12.2.4-30.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-mds-12.2.4-30.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-radosgw-12.2.4-30.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-selinux-12.2.4-30.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"cephmetrics-1.0.1-1.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"cephmetrics-ansible-1.0.1-1.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"cephmetrics-collectors-1.0.1-1.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"cephmetrics-grafana-plugins-1.0.1-1.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libcephfs-devel-12.2.4-30.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libcephfs2-12.2.4-30.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"librados-devel-12.2.4-30.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"librados2-12.2.4-30.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libradosstriper1-12.2.4-30.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"librbd-devel-12.2.4-30.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"librbd1-12.2.4-30.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"librgw-devel-12.2.4-30.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"librgw2-12.2.4-30.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nfs-ganesha-2.5.5-6.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nfs-ganesha-ceph-2.5.5-6.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nfs-ganesha-debuginfo-2.5.5-6.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nfs-ganesha-rgw-2.5.5-6.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-cephfs-12.2.4-30.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-rados-12.2.4-30.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-rbd-12.2.4-30.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-rgw-12.2.4-30.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rbd-mirror-12.2.4-30.el7cp")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ceph-ansible / ceph-base / ceph-common / ceph-debuginfo / ceph-fuse / etc");
  }
}
