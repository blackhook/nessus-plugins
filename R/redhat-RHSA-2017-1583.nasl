#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1583. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101100);
  script_version("3.10");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2016-8864", "CVE-2016-9131", "CVE-2016-9147", "CVE-2016-9444", "CVE-2017-3137");
  script_xref(name:"RHSA", value:"2017:1583");

  script_name(english:"RHEL 7 : bind (RHSA-2017:1583)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for bind is now available for Red Hat Enterprise Linux 7.2
Extended Update Support.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The Berkeley Internet Name Domain (BIND) is an implementation of the
Domain Name System (DNS) protocols. BIND includes a DNS server
(named); a resolver library (routines for applications to use when
interfacing with DNS); and tools for verifying that the DNS server is
operating correctly.

Security Fix(es) :

* A denial of service flaw was found in the way BIND handled responses
containing a DNAME answer. A remote attacker could use this flaw to
make named exit unexpectedly with an assertion failure via a specially
crafted DNS response. (CVE-2016-8864)

* A denial of service flaw was found in the way BIND processed a
response to an ANY query. A remote attacker could use this flaw to
make named exit unexpectedly with an assertion failure via a specially
crafted DNS response. (CVE-2016-9131)

* A denial of service flaw was found in the way BIND handled a query
response containing inconsistent DNSSEC information. A remote attacker
could use this flaw to make named exit unexpectedly with an assertion
failure via a specially crafted DNS response. (CVE-2016-9147)

* A denial of service flaw was found in the way BIND handled an
unusually-formed DS record response. A remote attacker could use this
flaw to make named exit unexpectedly with an assertion failure via a
specially crafted DNS response. (CVE-2016-9444)

* A denial of service flaw was found in the way BIND handled a query
response containing CNAME or DNAME resource records in an unusual
order. A remote attacker could use this flaw to make named exit
unexpectedly with an assertion failure via a specially crafted DNS
response. (CVE-2017-3137)

Red Hat would like to thank ISC for reporting these issues. Upstream
acknowledges Tony Finch (University of Cambridge) and Marco Davids
(SIDN Labs) as the original reporters of CVE-2016-8864.

Bug Fix(es) :

* ICANN is planning to perform a Root Zone DNSSEC Key Signing Key
(KSK) rollover during October 2017. Maintaining an up-to-date KSK is
essential for ensuring that validating DNS resolvers continue to
function following the rollover. (BZ#1459648)"
  );
  # https://kb.isc.org/article/AA-01434
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.isc.org/docs/aa-01434"
  );
  # https://kb.isc.org/article/AA-01439
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.isc.org/docs/aa-01439"
  );
  # https://kb.isc.org/article/AA-01440
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.isc.org/docs/aa-01440"
  );
  # https://kb.isc.org/article/AA-01441
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.isc.org/docs/aa-01441"
  );
  # https://kb.isc.org/article/AA-01466
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.isc.org/docs/aa-01466"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:1583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-8864"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-9131"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-9147"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-9444"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-3137"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-libs-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-lite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-pkcs11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-pkcs11-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-sdb-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/29");
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
if (! preg(pattern:"^7\.2([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.2", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:1583";
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
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"bind-9.9.4-29.el7_2.6")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"bind-9.9.4-29.el7_2.6")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"bind-chroot-9.9.4-29.el7_2.6")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"bind-chroot-9.9.4-29.el7_2.6")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", reference:"bind-debuginfo-9.9.4-29.el7_2.6")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", reference:"bind-devel-9.9.4-29.el7_2.6")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", reference:"bind-libs-9.9.4-29.el7_2.6")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", reference:"bind-libs-lite-9.9.4-29.el7_2.6")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", reference:"bind-license-9.9.4-29.el7_2.6")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", reference:"bind-lite-devel-9.9.4-29.el7_2.6")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"bind-pkcs11-9.9.4-29.el7_2.6")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"bind-pkcs11-9.9.4-29.el7_2.6")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", reference:"bind-pkcs11-devel-9.9.4-29.el7_2.6")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", reference:"bind-pkcs11-libs-9.9.4-29.el7_2.6")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"bind-pkcs11-utils-9.9.4-29.el7_2.6")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"bind-pkcs11-utils-9.9.4-29.el7_2.6")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"bind-sdb-9.9.4-29.el7_2.6")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"bind-sdb-9.9.4-29.el7_2.6")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"bind-sdb-chroot-9.9.4-29.el7_2.6")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"bind-sdb-chroot-9.9.4-29.el7_2.6")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"bind-utils-9.9.4-29.el7_2.6")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"bind-utils-9.9.4-29.el7_2.6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chroot / bind-debuginfo / bind-devel / bind-libs / etc");
  }
}
