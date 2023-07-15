#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1558. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100983);
  script_version("3.12");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2017-7514");
  script_xref(name:"RHSA", value:"2017:1558");

  script_name(english:"RHEL 6 : Satellite Server (RHSA-2017:1558)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Red Hat Satellite 5 for RHEL 6.0 is now available. Updated packages
which add various enhancements are now available for Red Hat Satellite
5.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat Satellite provides a solution to organizations requiring
absolute control over and privacy of the maintenance and package
deployment of their servers. It allows organizations to utilize the
benefits of Red Hat Network (RHN) without having to provide public
Internet access to their servers or other client systems.

Security Fix(es) :

A cross-site scripting (XSS) flaw was found in how the failed action
entry is processed in Satellite 5. A user able to specify a failed
action could exploit this flaw to perform XSS attacks against other
Satellite users. (CVE-2017-7514)

This issue was discovered by Jan Hutar (Red Hat).

This update introduces Red Hat Satellite 5.8.0. For the full list of
new features included in this release, see the Release Notes document
at :

https://access.redhat.com/documentation/en-US/Red_Hat_Satellite/5.8/

Note: Red Hat Satellite 5.8 and Red Hat Satellite Proxy 5.8 are
available for installation on Red Hat Enterprise Linux Server 6. For
full details, including supported architecture combinations, refer to
the Red Hat Satellite 5.8 Installation Guide.

All users of Red Hat Satellite are advised to install this newly
released version."
  );
  # https://access.redhat.com/documentation/en-US/Red_Hat_Satellite/5.8/
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/documentation/en-us/red_hat_satellite/5.8/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:1558"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-7514"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Filesys-Df");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Filesys-Df-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Params-Validate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Params-Validate-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql95-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql95-postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql95-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql95-postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql95-postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql95-postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql95-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-repo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-base-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-dobby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-setup-postgresql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/22");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:1558";
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

  if (! (rpm_exists(release:"RHEL6", rpm:"spacewalk-admin-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Satellite Server");

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"perl-Filesys-Df-0.92-8.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perl-Filesys-Df-0.92-8.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"perl-Filesys-Df-debuginfo-0.92-8.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perl-Filesys-Df-debuginfo-0.92-8.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"perl-Params-Validate-0.92-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"perl-Params-Validate-debuginfo-0.92-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"rh-postgresql95-postgresql-9.5.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rh-postgresql95-postgresql-9.5.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"rh-postgresql95-postgresql-contrib-9.5.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rh-postgresql95-postgresql-contrib-9.5.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"rh-postgresql95-postgresql-debuginfo-9.5.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rh-postgresql95-postgresql-debuginfo-9.5.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"rh-postgresql95-postgresql-libs-9.5.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rh-postgresql95-postgresql-libs-9.5.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"rh-postgresql95-postgresql-pltcl-9.5.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rh-postgresql95-postgresql-pltcl-9.5.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"rh-postgresql95-postgresql-server-9.5.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rh-postgresql95-postgresql-server-9.5.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"rh-postgresql95-runtime-2.2-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rh-postgresql95-runtime-2.2-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"satellite-repo-5.8.0.2-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-base-minimal-2.5.2-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-dobby-2.5.2-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-postgresql-server-9.5-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-setup-postgresql-2.5.0-27.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl-Filesys-Df / perl-Filesys-Df-debuginfo / perl-Params-Validate / etc");
  }
}
