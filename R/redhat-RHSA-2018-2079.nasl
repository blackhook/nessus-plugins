#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:2079. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110885);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/01");

  script_cve_id("CVE-2018-10855");
  script_xref(name:"RHSA", value:"2018:2079");

  script_name(english:"RHEL 7 : Virtualization Manager (RHSA-2018:2079)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Updated redhat-virtualization-host packages that fix several bugs and
add various enhancements are now available.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The redhat-virtualization-host packages provide the Red Hat
Virtualization Host. These packages include
redhat-release-virtualization-host, ovirt-node, and rhev-hypervisor.
Red Hat Virtualization Hosts (RHVH) are installed using a special
build of Red Hat Enterprise Linux with only the packages required to
host virtual machines. RHVH features a Cockpit user interface for
monitoring the host's resources and performing administrative tasks.

The ovirt-node-ng packages provide the Red Hat Virtualization Host.
These packages include redhat-release-virtualization-host, ovirt-node,
and rhev-hypervisor. Red Hat Virtualization Hosts (RHVH) are installed
using a special build of Red Hat Enterprise Linux with only the
packages required to host virtual machines. RHVH features a Cockpit
user interface for monitoring the host's resources and performing
administrative tasks.

The following packages have been upgraded to a later upstream version:
imgbased (1.0.20), redhat-release-virtualization-host (4.2),
redhat-virtualization-host (4.2). (BZ#1590664)

Security Fix(es) :

* ansible: Failed tasks do not honour no_log option allowing for
secrets to be disclosed in logs (CVE-2018-10855)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank Tobias Henkel (BMW Car IT GmbH) for
reporting this issue.

Bug Fix(es) :

* Previously, if systems were configured to skip Logical Volume
Manager (LVM) clusters, imgbased sees output that is unrelated to the
Logical Volumes that are being queried.

As a result, imgbased failed to parse the output, causing Red Hat
Virtualization Host updates to fail.

In this release imgbased now ignores output from skipped clusters
enabling imgbased LVM commands to return successfully. (BZ#1568414)

Enhancement(s) :

* Starting from version 4.0, Red Hat Virtualization Hosts could not be
deployed from Satellite, and therefore could not take advantage of
Satellite's tooling features.

In this release, Red Hat Virtualization Hosts can now be deployed from
Satellite 6.3.2 and later. (BZ#1484532)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:2079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-10855"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:imgbased");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-imgbased");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-release-virtualization-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-virtualization-host-image-update");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-virtualization-host-image-update-placeholder");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/03");
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
  rhsa = "RHSA-2018:2079";
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

  if (! (rpm_exists(release:"RHEL7", rpm:"redhat-virtualization-host-4.2"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Red Hat Virtualization 4");

  if (rpm_check(release:"RHEL7", reference:"imgbased-1.0.20-0.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-imgbased-1.0.20-0.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"redhat-release-virtualization-host-4.2-4.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"redhat-virtualization-host-image-update-4.2-20180622.0.el7_5")) flag++;
  if (rpm_check(release:"RHEL7", reference:"redhat-virtualization-host-image-update-placeholder-4.2-4.3.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "imgbased / python-imgbased / redhat-release-virtualization-host / etc");
  }
}
