#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1549 and 
# CentOS Errata and Security Advisory 2009:1549 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67069);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-3490");
  script_bugtraq_id(36205);
  script_xref(name:"RHSA", value:"2009:1549");

  script_name(english:"CentOS 3 / 4 / 5 : wget (CESA-2009:1549)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated wget package that fixes a security issue is now available
for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

GNU Wget is a file retrieval utility that can use HTTP, HTTPS, and
FTP.

Daniel Stenberg reported that Wget is affected by the previously
published 'null prefix attack', caused by incorrect handling of NULL
characters in X.509 certificates. If an attacker is able to get a
carefully-crafted certificate signed by a trusted Certificate
Authority, the attacker could use the certificate during a
man-in-the-middle attack and potentially confuse Wget into accepting
it by mistake. (CVE-2009-3490)

Wget users should upgrade to this updated package, which contains a
backported patch to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-November/016298.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5cd2ef30"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-November/016299.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fbb0bddb"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-November/016306.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c790cb2e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-November/016307.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6a57fec9"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-November/016324.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e561afa4"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-November/016325.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?840b8887"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected wget package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wget");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"wget-1.10.2-0.30E.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"wget-1.10.2-0.30E.1")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"wget-1.10.2-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"wget-1.10.2-1.el4_8.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"wget-1.11.4-2.el5_4.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wget");
}
