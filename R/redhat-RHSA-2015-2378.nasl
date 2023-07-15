#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2378. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86986);
  script_version("2.11");
  script_cvs_date("Date: 2019/10/24 15:35:40");

  script_cve_id("CVE-2015-3455");
  script_xref(name:"RHSA", value:"2015:2378");

  script_name(english:"RHEL 7 : squid (RHSA-2015:2378)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated squid packages that fix one security issue and two bugs are
now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Squid is a high-performance proxy caching server for web clients,
supporting FTP, Gopher, and HTTP data objects.

It was found that Squid configured with client-first SSL-bump did not
correctly validate X.509 server certificate host name fields. A
man-in-the-middle attacker could use this flaw to spoof a Squid server
using a specially crafted X.509 certificate. (CVE-2015-3455)

This update fixes the following bugs :

* Previously, the squid process did not handle file descriptors
correctly when receiving Simple Network Management Protocol (SNMP)
requests. As a consequence, the process gradually accumulated open
file descriptors. This bug has been fixed and squid now handles SNMP
requests correctly, closing file descriptors when necessary.
(BZ#1198778)

* Under high system load, the squid process sometimes terminated
unexpectedly with a segmentation fault during reboot. This update
provides better memory handling during reboot, thus fixing this bug.
(BZ#1225640)

Users of squid are advised to upgrade to these updated packages, which
fix these bugs. After installing this update, the squid service will
be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2015:2378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-3455"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected squid, squid-debuginfo and / or squid-sysvinit
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:squid-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:squid-sysvinit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2015:2378";
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
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"squid-3.3.8-26.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"squid-3.3.8-26.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"squid-debuginfo-3.3.8-26.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"squid-debuginfo-3.3.8-26.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"squid-sysvinit-3.3.8-26.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"squid-sysvinit-3.3.8-26.el7")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squid / squid-debuginfo / squid-sysvinit");
  }
}
