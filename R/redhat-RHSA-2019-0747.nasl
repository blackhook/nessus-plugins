#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:0747. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124015);
  script_version("1.6");
  script_cvs_date("Date: 2020/01/23");

  script_cve_id("CVE-2018-19039");
  script_xref(name:"RHSA", value:"2019:0747");

  script_name(english:"RHEL 7 : Red Hat Ceph Storage 2.5 (RHSA-2019:0747)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for ceph and grafana is now available for Red Hat Ceph
Storage 2.5 for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat Ceph Storage is a scalable, open, software-defined storage
platform that combines the most stable version of the Ceph storage
system with a Ceph management platform, deployment utilities, and
support services.

Security Fix(es) :

* grafana: File exfiltration (CVE-2018-19039)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Bug Fix(es) :

* This issue was discovered with OpenStack Cinder Backup when
'rados_connect_timeout' was set. Normally the timeout is not enabled.
If the cluster was highly loaded the timeout could be reached, causing
the segfault. With this update to Red Hat Ceph Storage, if the timeout
is reached a segfault no longer occurs. (BZ#1655685)

* With this release, you now have the ability to reset a user's
statistics using the 'radosgw-admin' command. In previous versions,
the user's recorded statistics diverged from the actual statistics.
When using the '--reset-stats' option with the 'radosgw-admin'
command, along with specifying the Ceph Object Gateway user, the stats
will be recalculated. (BZ#1673217)

* In the duplicate checking code an inconsistency was found that
caused duplicate indices to be added, instead of trimming them. The
duplicate checking code logic has been fixed, making adding and
trimming duplicate indices consistent, which results in correctly
trimming duplicate indices. (BZ#1676709)

* Two bugs were found in the garbage collection list iteration logic.
One of these bugs was a race condition when doing system restarts.
These bugs were causing higher-than-expected workloads and stalling in
garbage collection processing. Issues with list truncation and entry
deletion were fixed, reducing the potential for garbage collection
stalls and high-read I/O during garbage collection removal.
(BZ#1680050)

* Due to a bug in multi-site sync of versioning-suspended buckets,
certain object versioning attributes were overwritten with incorrect
values. Consequently, the objects failed to sync and attempted to
retry endlessly, blocking further sync progress. With this update, the
sync process no longer overwrites versioning attributes. In addition,
any broken attributes are now detected and repaired. As a result,
objects are synced correctly in versioning-suspended buckets.
(BZ#1690927)

* Previously, bucket indices could include 'false entries' that did
not represent actual objects and that resulted from a prior bug.
Consequently, during the process of deleting such buckets,
encountering a false entry caused the process to stop and return an
error code. With this update, when a false entry is encountered, Ceph
ignores it, and deleting buckets with false entries works as expected.
(BZ#1690930)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:0747"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-19039"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-radosgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grafana");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcephfs1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcephfs1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librados2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librados2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librbd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librbd1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librgw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librgw2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rbd-mirror");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2019:0747";
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

  if (! (rpm_exists(release:"RHEL7", rpm:"ceph-mon-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Ceph Storage");

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-base-10.2.10-49.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-common-10.2.10-49.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-debuginfo-10.2.10-49.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-fuse-10.2.10-49.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-mds-10.2.10-49.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-radosgw-10.2.10-49.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-selinux-10.2.10-49.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"grafana-4.3.2-4.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libcephfs1-10.2.10-49.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libcephfs1-devel-10.2.10-49.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"librados2-10.2.10-49.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"librados2-devel-10.2.10-49.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"librbd1-10.2.10-49.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"librbd1-devel-10.2.10-49.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"librgw2-10.2.10-49.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"librgw2-devel-10.2.10-49.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-cephfs-10.2.10-49.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-rados-10.2.10-49.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-rbd-10.2.10-49.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rbd-mirror-10.2.10-49.el7cp")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ceph-base / ceph-common / ceph-debuginfo / ceph-fuse / ceph-mds / etc");
  }
}
