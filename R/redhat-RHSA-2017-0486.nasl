#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0486. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97929);
  script_version("3.13");
  script_cvs_date("Date: 2019/10/24 15:35:42");

  script_cve_id("CVE-2015-1795");
  script_xref(name:"RHSA", value:"2017:0486");

  script_name(english:"RHEL 7 : Gluster Storage (RHSA-2017:0486)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update is now available for Red Hat Gluster Storage 3.2 on Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat Gluster Storage is a software only scale-out storage solution
that provides flexible and affordable unstructured data storage. It
unifies data storage and infrastructure, increases performance, and
improves availability and manageability to meet enterprise-level
storage challenges.

The following packages have been upgraded to a later upstream version:
glusterfs (3.8.4), redhat-storage-server (3.2.0.2), vdsm (4.17.33).
(BZ# 1362376)

Security Fix(es) :

* It was found that glusterfs-server RPM package would write file with
predictable name into world readable /tmp directory. A local attacker
could potentially use this flaw to escalate their privileges to root
by modifying the shell script during the installation of the
glusterfs-server package. (CVE-2015-1795)

This issue was discovered by Florian Weimer of Red Hat Product
Security.

Bug Fix(es) :

* Bricks remain stopped if server quorum is no longer met, or if
server quorum is disabled, to ensure that bricks in maintenance are
not started incorrectly. (BZ#1340995)

* The metadata cache translator has been updated to improve Red Hat
Gluster Storage performance when reading small files. (BZ#1427783)

* The 'gluster volume add-brick' command is no longer allowed when the
replica count has increased and any replica bricks are unavailable.
(BZ# 1404989)

* Split-brain resolution commands work regardless of whether
client-side heal or the self-heal daemon are enabled. (BZ#1403840)

Enhancement(s) :

* Red Hat Gluster Storage now provides Transport Layer Security
support for Samba and NFS-Ganesha. (BZ#1340608, BZ#1371475)

* A new reset-sync-time option enables resetting the sync time
attribute to zero when required. (BZ#1205162)

* Tiering demotions are now triggered at most 5 seconds after a
hi-watermark breach event. Administrators can use the
cluster.tier-query-limit volume parameter to specify the number of
records extracted from the heat database during demotion. (BZ#1361759)

* The /var/log/glusterfs/etc-glusterfs-glusterd.vol.log file is now
named / var/log/glusterfs/glusterd.log. (BZ#1306120)

* The 'gluster volume attach-tier/detach-tier' commands are considered
deprecated in favor of the new commands, 'gluster volume tier VOLNAME
attach/detach'. (BZ#1388464)

* The HA_VOL_SERVER parameter in the ganesha-ha.conf file is no longer
used by Red Hat Gluster Storage. (BZ#1348954)

* The volfile server role can now be passed to another server when a
server is unavailable. (BZ#1351949)

* Ports can now be reused when they stop being used by another
service. (BZ# 1263090)

* The thread pool limit for the rebalance process is now dynamic, and
is determined based on the number of available cores. (BZ#1352805)

* Brick verification at reboot now uses UUID instead of brick path.
(BZ# 1336267)

* LOGIN_NAME_MAX is now used as the maximum length for the slave user
instead of __POSIX_LOGIN_NAME_MAX, allowing for up to 256 characters
including the NULL byte. (BZ#1400365)

* The client identifier is now included in the log message to make it
easier to determine which client failed to connect. (BZ#1333885)"
  );
  # https://access.redhat.com/documentation/en-us/red_hat_gluster_storage/3.2/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3a106d44"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:0486"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-1795"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-api-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-client-xlators");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-events");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-ganesha");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-geo-replication");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-rdma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-storage-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-debug-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-hook-ethtool-options");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-hook-faqemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-hook-openstacknet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-hook-qemucmdline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-infra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-jsonrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-yajsonrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2017:0486";
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

  if (! (rpm_exists(release:"RHEL7", rpm:"glusterfs-server"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Gluster Storage");

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glusterfs-3.8.4-18.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glusterfs-api-3.8.4-18.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glusterfs-api-devel-3.8.4-18.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glusterfs-cli-3.8.4-18.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glusterfs-client-xlators-3.8.4-18.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glusterfs-debuginfo-3.8.4-18.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glusterfs-devel-3.8.4-18.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glusterfs-events-3.8.4-18.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glusterfs-fuse-3.8.4-18.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glusterfs-ganesha-3.8.4-18.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glusterfs-geo-replication-3.8.4-18.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glusterfs-libs-3.8.4-18.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glusterfs-rdma-3.8.4-18.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glusterfs-server-3.8.4-18.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-gluster-3.8.4-18.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"redhat-storage-server-3.2.0.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"vdsm-4.17.33-1.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"vdsm-cli-4.17.33-1.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"vdsm-debug-plugin-4.17.33-1.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"vdsm-gluster-4.17.33-1.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"vdsm-hook-ethtool-options-4.17.33-1.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"vdsm-hook-faqemu-4.17.33-1.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"vdsm-hook-openstacknet-4.17.33-1.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"vdsm-hook-qemucmdline-4.17.33-1.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"vdsm-infra-4.17.33-1.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"vdsm-jsonrpc-4.17.33-1.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"vdsm-python-4.17.33-1.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"vdsm-tests-4.17.33-1.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"vdsm-xmlrpc-4.17.33-1.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"vdsm-yajsonrpc-4.17.33-1.1.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glusterfs / glusterfs-api / glusterfs-api-devel / glusterfs-cli / etc");
  }
}
