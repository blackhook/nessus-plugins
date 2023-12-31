#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0078. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88479);
  script_version("2.11");
  script_cvs_date("Date: 2019/10/24 15:35:41");

  script_cve_id("CVE-2014-8500", "CVE-2015-5477", "CVE-2015-5722", "CVE-2015-8000");
  script_xref(name:"RHSA", value:"2016:0078");

  script_name(english:"RHEL 6 : bind (RHSA-2016:0078)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated bind packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6.4 and 6.5 Advanced Update
Support.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The Berkeley Internet Name Domain (BIND) is an implementation of the
Domain Name System (DNS) protocols. BIND includes a DNS server
(named); a resolver library (routines for applications to use when
interfacing with DNS); and tools for verifying that the DNS server is
operating correctly.

A denial of service flaw was found in the way BIND followed DNS
delegations. A remote attacker could use a specially crafted zone
containing a large number of referrals which, when looked up and
processed, would cause named to use excessive amounts of memory or
crash. (CVE-2014-8500)

A flaw was found in the way BIND handled requests for TKEY DNS
resource records. A remote attacker could use this flaw to make named
(functioning as an authoritative DNS server or a DNS resolver) exit
unexpectedly with an assertion failure via a specially crafted DNS
request packet. (CVE-2015-5477)

A denial of service flaw was found in the way BIND parsed certain
malformed DNSSEC keys. A remote attacker could use this flaw to send a
specially crafted DNS query (for example, a query requiring a response
from a zone containing a deliberately malformed key) that would cause
named functioning as a validating resolver to crash. (CVE-2015-5722)

A denial of service flaw was found in the way BIND processed certain
records with malformed class attributes. A remote attacker could use
this flaw to send a query to request a cached record with a malformed
class attribute that would cause named functioning as an authoritative
or recursive server to crash. (CVE-2015-8000)

Note: This issue affects authoritative servers as well as recursive
servers, however authoritative servers are at limited risk if they
perform authentication when making recursive queries to resolve
addresses for servers listed in NS RRSETs.

Red Hat would like to thank ISC for reporting the CVE-2015-5477,
CVE-2015-5722, and CVE-2015-8000 issues. Upstream acknowledges
Jonathan Foote as the original reporter of CVE-2015-5477, and Hanno
Bock as the original reporter of CVE-2015-5722.

All bind users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the update, the BIND daemon (named) will be restarted automatically."
  );
  # https://kb.isc.org/article/AA-01216
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.isc.org/docs/aa-01216"
  );
  # https://kb.isc.org/article/AA-01272
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.isc.org/docs/aa-01272"
  );
  # https://kb.isc.org/article/AA-01287
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.isc.org/docs/aa-01287"
  );
  # https://kb.isc.org/article/AA-01317
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.isc.org/docs/aa-01317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2016:0078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-8500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-5477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-5722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-8000"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(6\.4|6\.5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.4 / 6.5", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:0078";
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
{  sp = get_kb_item("Host/RedHat/minor_release");
  if (isnull(sp)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");

  flag = 0;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"bind-9.8.2-0.17.rc1.el6_4.7")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"bind-9.8.2-0.23.rc1.el6_5.2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"bind-chroot-9.8.2-0.17.rc1.el6_4.7")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"bind-chroot-9.8.2-0.23.rc1.el6_5.2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"bind-debuginfo-9.8.2-0.17.rc1.el6_4.7")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"bind-debuginfo-9.8.2-0.23.rc1.el6_5.2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"bind-debuginfo-9.8.2-0.17.rc1.el6_4.7")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"bind-debuginfo-9.8.2-0.23.rc1.el6_5.2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"bind-devel-9.8.2-0.17.rc1.el6_4.7")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"bind-devel-9.8.2-0.23.rc1.el6_5.2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"bind-devel-9.8.2-0.17.rc1.el6_4.7")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"bind-devel-9.8.2-0.23.rc1.el6_5.2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"bind-libs-9.8.2-0.17.rc1.el6_4.7")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"bind-libs-9.8.2-0.23.rc1.el6_5.2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"bind-libs-9.8.2-0.17.rc1.el6_4.7")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"bind-libs-9.8.2-0.23.rc1.el6_5.2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"bind-sdb-9.8.2-0.17.rc1.el6_4.7")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"bind-sdb-9.8.2-0.23.rc1.el6_5.2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"bind-utils-9.8.2-0.17.rc1.el6_4.7")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"bind-utils-9.8.2-0.23.rc1.el6_5.2")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chroot / bind-debuginfo / bind-devel / bind-libs / etc");
  }
}
