#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0731 and 
# CentOS Errata and Security Advisory 2007:0731 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25832);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-3387");
  script_bugtraq_id(25124);
  script_xref(name:"RHSA", value:"2007:0731");

  script_name(english:"CentOS 3 / 4 / 5 : tetex (CESA-2007:0731)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tetex packages that fix a security issue in PDF handling are
now available for Red Hat Enterprise Linux 2.1, 3, 4, and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

TeTeX is an implementation of TeX. TeX takes a text file and a set of
formatting commands as input and creates a typesetter-independent .dvi
(DeVice Independent) file as output.

Maurycy Prodeus discovered an integer overflow flaw in the processing
of PDF files. An attacker could create a malicious PDF file that would
cause TeTeX to crash or potentially execute arbitrary code when
opened. (CVE-2007-3387)

All users of TeTeX should upgrade to these updated packages, which
contain a backported patch to resolve this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-August/014126.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?99d75935"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-August/014127.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b6dd1d33"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-August/014128.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4205a7d2"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-August/014129.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?23af2d89"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-August/014130.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ccf8606b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-August/014131.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?295fb5fc"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-August/014133.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fbc22a70"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-August/014134.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7406ad9b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tetex packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tetex-afm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tetex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tetex-dvips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tetex-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tetex-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tetex-xdvi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-3", reference:"tetex-1.0.7-67.10")) flag++;
if (rpm_check(release:"CentOS-3", reference:"tetex-afm-1.0.7-67.10")) flag++;
if (rpm_check(release:"CentOS-3", reference:"tetex-doc-1.0.7-67.10")) flag++;
if (rpm_check(release:"CentOS-3", reference:"tetex-dvips-1.0.7-67.10")) flag++;
if (rpm_check(release:"CentOS-3", reference:"tetex-fonts-1.0.7-67.10")) flag++;
if (rpm_check(release:"CentOS-3", reference:"tetex-latex-1.0.7-67.10")) flag++;
if (rpm_check(release:"CentOS-3", reference:"tetex-xdvi-1.0.7-67.10")) flag++;

if (rpm_check(release:"CentOS-4", reference:"tetex-2.0.2-22.0.1.EL4.8")) flag++;
if (rpm_check(release:"CentOS-4", reference:"tetex-afm-2.0.2-22.0.1.EL4.8")) flag++;
if (rpm_check(release:"CentOS-4", reference:"tetex-doc-2.0.2-22.0.1.EL4.8")) flag++;
if (rpm_check(release:"CentOS-4", reference:"tetex-dvips-2.0.2-22.0.1.EL4.8")) flag++;
if (rpm_check(release:"CentOS-4", reference:"tetex-fonts-2.0.2-22.0.1.EL4.8")) flag++;
if (rpm_check(release:"CentOS-4", reference:"tetex-latex-2.0.2-22.0.1.EL4.8")) flag++;
if (rpm_check(release:"CentOS-4", reference:"tetex-xdvi-2.0.2-22.0.1.EL4.8")) flag++;

if (rpm_check(release:"CentOS-5", reference:"tetex-3.0-33.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tetex-afm-3.0-33.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tetex-doc-3.0-33.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tetex-dvips-3.0-33.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tetex-fonts-3.0-33.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tetex-latex-3.0-33.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tetex-xdvi-3.0-33.1.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tetex / tetex-afm / tetex-doc / tetex-dvips / tetex-fonts / etc");
}
