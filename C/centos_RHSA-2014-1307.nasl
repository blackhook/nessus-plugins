#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1307 and 
# CentOS Errata and Security Advisory 2014:1307 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77918);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2014-1568");
  script_bugtraq_id(70116);
  script_xref(name:"RHSA", value:"2014:1307");

  script_name(english:"CentOS 5 / 6 / 7 : nss (CESA-2014:1307)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated nss packages that fix one security issue are now available for
Red Hat Enterprise Linux 5, 6, and 7.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications. Netscape Portable Runtime (NSPR) provides
platform independence for non-GUI operating system facilities.

A flaw was found in the way NSS parsed ASN.1 (Abstract Syntax Notation
One) input from certain RSA signatures. A remote attacker could use
this flaw to forge RSA certificates by providing a specially crafted
signature to an application using NSS. (CVE-2014-1568)

Red Hat would like to thank the Mozilla project for reporting this
issue. Upstream acknowledges Antoine Delignat-Lavaud and Intel Product
Security Incident Response Team as the original reporters.

All NSS users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing
this update, applications using NSS must be restarted for this update
to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-September/020595.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6e10a79e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-September/020598.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c2020969"
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-September/020653.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3579e461"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected nss packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-1568");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-softokn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-softokn-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-softokn-freebl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-softokn-freebl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^(5|6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x / 6.x / 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"nss-3.16.1-4.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-devel-3.16.1-4.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-pkcs11-devel-3.16.1-4.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-tools-3.16.1-4.el5_11")) flag++;

if (rpm_check(release:"CentOS-6", reference:"nss-3.16.1-7.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-devel-3.16.1-7.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-pkcs11-devel-3.16.1-7.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-softokn-3.14.3-12.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-softokn-devel-3.14.3-12.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-softokn-freebl-3.14.3-12.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-softokn-freebl-devel-3.14.3-12.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-sysinit-3.16.1-7.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-tools-3.16.1-7.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-util-3.16.1-2.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-util-devel-3.16.1-2.el6_5")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-3.16.2-7.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-devel-3.16.2-7.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-pkcs11-devel-3.16.2-7.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-softokn-3.16.2-2.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-softokn-devel-3.16.2-2.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-softokn-freebl-3.16.2-2.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-softokn-freebl-devel-3.16.2-2.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-sysinit-3.16.2-7.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-tools-3.16.2-7.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-util-3.16.2-2.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-util-devel-3.16.2-2.el7_0")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss / nss-devel / nss-pkcs11-devel / nss-softokn / etc");
}
