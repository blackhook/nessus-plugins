#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:0805. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108985);
  script_version("1.9");
  script_cvs_date("Date: 2019/10/24 15:35:44");

  script_cve_id("CVE-2014-9402", "CVE-2015-5180", "CVE-2017-12132", "CVE-2017-15670", "CVE-2017-15804", "CVE-2018-1000001");
  script_xref(name:"RHSA", value:"2018:0805");

  script_name(english:"RHEL 7 : glibc (RHSA-2018:0805)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for glibc is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The glibc packages provide the standard C libraries (libc), POSIX
thread libraries (libpthread), standard math libraries (libm), and the
name service cache daemon (nscd) used by multiple programs on the
system. Without these libraries, the Linux system cannot function
correctly.

Security Fix(es) :

* glibc: realpath() buffer underflow when getcwd() returns relative
path allows privilege escalation (CVE-2018-1000001)

* glibc: Buffer overflow in glob with GLOB_TILDE (CVE-2017-15670)

* glibc: Buffer overflow during unescaping of user names with the ~
operator (CVE-2017-15804)

* glibc: denial of service in getnetbyname function (CVE-2014-9402)

* glibc: DNS resolver NULL pointer dereference with crafted record
type (CVE-2015-5180)

* glibc: Fragmentation attacks possible when EDNS0 is enabled
(CVE-2017-12132)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank halfdog for reporting CVE-2018-1000001.
The CVE-2015-5180 issue was discovered by Florian Weimer (Red Hat
Product Security).

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.5 Release Notes linked from the References section."
  );
  # https://access.redhat.com/documentation/en-US/red_hat_enterprise_linux/7/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dde41582"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:0805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-9402"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-5180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-12132"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-15670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-15804"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-1000001"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'glibc "realpath()" Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-debuginfo-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/11");
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
  rhsa = "RHSA-2018:0805";
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
  if (rpm_check(release:"RHEL7", reference:"glibc-2.17-222.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"glibc-common-2.17-222.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glibc-common-2.17-222.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"glibc-debuginfo-2.17-222.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"glibc-debuginfo-common-2.17-222.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"glibc-devel-2.17-222.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"glibc-headers-2.17-222.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glibc-headers-2.17-222.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"glibc-static-2.17-222.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"glibc-utils-2.17-222.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glibc-utils-2.17-222.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"nscd-2.17-222.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nscd-2.17-222.el7")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / glibc-debuginfo / glibc-debuginfo-common / etc");
  }
}
