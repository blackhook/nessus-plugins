#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:3888 and 
# CentOS Errata and Security Advisory 2019:3888 respectively.
#

include("compat.inc");

if (description)
{
  script_id(131569);
  script_version("1.4");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2019-14869");
  script_xref(name:"RHSA", value:"2019:3888");

  script_name(english:"CentOS 7 : ghostscript (CESA-2019:3888)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for ghostscript is now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The Ghostscript suite contains utilities for rendering PostScript and
PDF documents. Ghostscript translates PostScript code to common bitmap
formats so that the code can be displayed or printed.

Security Fix(es) :

* ghostscript: -dSAFER escape in .charkeys (701841) (CVE-2019-14869)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  # https://lists.centos.org/pipermail/centos-announce/2019-December/023522.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9ca0f6f0"
  );
  # https://lists.centos.org/pipermail/centos-announce/2019-December/035560.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7e1d8280"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ghostscript packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14869");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ghostscript-cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ghostscript-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ghostscript-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ghostscript-9.25-2.el7_7.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ghostscript-cups-9.25-2.el7_7.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ghostscript-doc-9.25-2.el7_7.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ghostscript-gtk-9.25-2.el7_7.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgs-9.25-2.el7_7.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgs-devel-9.25-2.el7_7.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript / ghostscript-cups / ghostscript-doc / ghostscript-gtk / etc");
}
