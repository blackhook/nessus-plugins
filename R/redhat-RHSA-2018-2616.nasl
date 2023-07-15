#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:2616. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117322);
  script_version("1.8");
  script_cvs_date("Date: 2019/10/24 15:35:45");

  script_cve_id("CVE-2018-1127");
  script_xref(name:"RHSA", value:"2018:2616");

  script_name(english:"RHEL 7 : Storage Server (RHSA-2018:2616)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Red Hat Gluster Storage Wed Administration packages that fix
one security issue, several bugs, and add various enhancements are now
available for Red Hat Gluster Storage 3.4 on Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Low. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link (s) in the References section.

Red Hat Gluster Storage Web Administration includes a fully automated
setup based on Ansible and provides deep metrics and insights into
active Gluster storage pools by using the Grafana platform. Red Hat
Gluster Storage Web Administration provides a dashboard view which
allows an administrator to get a view of overall gluster health in
terms of hosts, volumes, bricks, and other components of GlusterFS.

Security Fix(es) :

* tendrl-api: Improper cleanup of session token can allow attackers to
hijack user sessions (CVE-2018-1127)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

This issue was discovered by Filip Balak (Red Hat).

Additional Changes :

These updated Red Hat Gluster Storage Wed Administration packages
include numerous bug fixes and enhancements. Space precludes
documenting all of these changes in this advisory. Users are directed
to the Red Hat Gluster Storage 3.4 Release Notes for information on
the most significant of these changes :

https://access.redhat.com/site/documentation/en-US/red_hat_gluster_sto
rage/ 3.4/html/3.4_release_notes/

All users of Red Hat Gluster Storage are advised to upgrade to these
updated packages, which provide numerous bug fixes and enhancements."
  );
  # https://access.redhat.com/site/documentation/en-US/red_hat_gluster_storage/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d6c2aef9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:2616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-1127"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-flask");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-flask-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-itsdangerous");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tendrl-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tendrl-gluster-integration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tendrl-node-agent");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/06");
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
  rhsa = "RHSA-2018:2616";
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

  if (! (rpm_exists(release:"RHEL7", rpm:"glusterfs-3.12.2"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Storage Server");

  if (rpm_check(release:"RHEL7", reference:"python-flask-0.10.1-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-flask-doc-0.10.1-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-itsdangerous-0.23-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tendrl-commons-1.6.3-12.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tendrl-gluster-integration-1.6.3-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tendrl-node-agent-1.6.3-10.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-flask / python-flask-doc / python-itsdangerous / etc");
  }
}
