#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0916 and 
# CentOS Errata and Security Advisory 2014:0916 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76685);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2014-1544");
  script_bugtraq_id(68816);
  script_xref(name:"RHSA", value:"2014:0916");

  script_name(english:"CentOS 5 / 7 : nspr / nss (CESA-2014:0916)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated nss and nspr packages that fix one security issue are now
available for Red Hat Enterprise Linux 5 and 7.

The Red Hat Security Response Team has rated this update as having
Critical security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications. Netscape Portable Runtime (NSPR) provides
platform independence for non-GUI operating system facilities.

A race condition was found in the way NSS verified certain
certificates. A remote attacker could use this flaw to crash an
application using NSS or, possibly, execute arbitrary code with the
privileges of the user running that application. (CVE-2014-1544)

Red Hat would like to thank the Mozilla project for reporting
CVE-2014-1544. Upstream acknowledges Tyson Smith and Jesse
Schwartzentruber as the original reporters.

Users of NSS and NSPR are advised to upgrade to these updated
packages, which correct this issue. After installing this update,
applications using NSS or NSPR must be restarted for this update to
take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-July/020427.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?277e9bd5"
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-July/020428.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a27bf1c8"
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-July/020432.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?873c4025"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nspr and / or nss packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-1544");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/23");
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
if (! preg(pattern:"^(5|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x / 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"nspr-4.10.6-1.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nspr-devel-4.10.6-1.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-3.15.3-7.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-devel-3.15.3-7.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-pkcs11-devel-3.15.3-7.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-tools-3.15.3-7.el5_10")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nspr-4.10.6-1.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nspr-devel-4.10.6-1.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-3.15.4-7.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-devel-3.15.4-7.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-pkcs11-devel-3.15.4-7.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-sysinit-3.15.4-7.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-tools-3.15.4-7.el7_0")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nspr / nspr-devel / nss / nss-devel / nss-pkcs11-devel / etc");
}
