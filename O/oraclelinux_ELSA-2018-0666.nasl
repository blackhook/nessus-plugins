#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2018:0666 and 
# Oracle Linux Security Advisory ELSA-2018-0666 respectively.
#

include("compat.inc");

if (description)
{
  script_id(109104);
  script_version("1.2");
  script_cvs_date("Date: 2019/09/27 13:00:38");

  script_cve_id("CVE-2017-11368", "CVE-2017-7562");
  script_xref(name:"RHSA", value:"2018:0666");

  script_name(english:"Oracle Linux 7 : krb5 (ELSA-2018-0666)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2018:0666 :

An update for krb5 is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Kerberos is a network authentication system, which can improve the
security of your network by eliminating the insecure practice of
sending passwords over the network in unencrypted form. It allows
clients and servers to authenticate to each other with the help of a
trusted third party, the Kerberos key distribution center (KDC).

Security Fix(es) :

* krb5: Authentication bypass by improper validation of certificate
EKU and SAN (CVE-2017-7562)

* krb5: Invalid S4U2Self or S4U2Proxy request causes assertion failure
(CVE-2017-11368)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.5 Release Notes linked from the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2018-April/007610.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected krb5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-pkinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-server-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libkadm5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"krb5-devel-1.15.1-18.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"krb5-libs-1.15.1-18.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"krb5-pkinit-1.15.1-18.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"krb5-server-1.15.1-18.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"krb5-server-ldap-1.15.1-18.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"krb5-workstation-1.15.1-18.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libkadm5-1.15.1-18.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-devel / krb5-libs / krb5-pkinit / krb5-server / etc");
}
