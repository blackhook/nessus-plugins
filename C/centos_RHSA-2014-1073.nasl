#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1073 and 
# CentOS Errata and Security Advisory 2014:1073 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77239);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2014-1492");
  script_bugtraq_id(66356);
  script_xref(name:"RHSA", value:"2014:1073");

  script_name(english:"CentOS 7 : nss / nss-softokn / nss-util (CESA-2014:1073)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated nss, nss-util, and nss-softokn packages that fix one security
issue, several bugs, and add various enhancements are now available
for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Low security
impact. A Common Vulnerability Scoring System (CVSS) base score, which
gives a detailed severity rating, is available from the CVE link in
the References section.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications. Applications built with NSS can support SSLv3,
TLS, and other security standards.

It was found that the implementation of Internationalizing Domain
Names in Applications (IDNA) hostname matching in NSS did not follow
the RFC 6125 recommendations. This could lead to certain invalid
certificates with international characters to be accepted as valid.
(CVE-2014-1492)

In addition, the nss, nss-util, and nss-softokn packages have been
upgraded to upstream version 3.16.2, which provides a number of bug
fixes and enhancements over the previous versions. (BZ#1124659)

Users of NSS are advised to upgrade to these updated packages, which
correct these issues and add these enhancements. After installing this
update, applications using NSS must be restarted for this update to
take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-August/020497.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b8aca45a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-August/020498.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?490e7259"
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-August/020499.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8e6c6427"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nss, nss-softokn and / or nss-util packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-1492");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/19");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-3.16.2-2.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-devel-3.16.2-2.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-pkcs11-devel-3.16.2-2.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-softokn-3.16.2-1.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-softokn-devel-3.16.2-1.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-softokn-freebl-3.16.2-1.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-softokn-freebl-devel-3.16.2-1.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-sysinit-3.16.2-2.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-tools-3.16.2-2.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-util-3.16.2-1.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-util-devel-3.16.2-1.el7_0")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
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
