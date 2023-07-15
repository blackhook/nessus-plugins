#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2551 and 
# CentOS Errata and Security Advisory 2017:2551 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102884);
  script_version("3.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-9775", "CVE-2017-9776");
  script_xref(name:"RHSA", value:"2017:2551");

  script_name(english:"CentOS 7 : poppler (CESA-2017:2551)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for poppler is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Poppler is a Portable Document Format (PDF) rendering library, used by
applications such as Evince.

Security Fix(es) :

* A stack-based buffer overflow was found in the poppler library. An
attacker could create a malicious PDF file that would cause
applications that use poppler (such as Evince) to crash, or
potentially execute arbitrary code when opened. (CVE-2017-9775)

* An integer overflow leading to heap-based buffer overflow was found
in the poppler library. An attacker could create a malicious PDF file
that would cause applications that use poppler (such as Evince) to
crash, or potentially execute arbitrary code when opened.
(CVE-2017-9776)"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004691.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?daf91fb8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected poppler packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9776");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-cpp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-qt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-0.26.5-17.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-cpp-0.26.5-17.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-cpp-devel-0.26.5-17.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-demos-0.26.5-17.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-devel-0.26.5-17.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-glib-0.26.5-17.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-glib-devel-0.26.5-17.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-qt-0.26.5-17.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-qt-devel-0.26.5-17.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-utils-0.26.5-17.el7_4")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "poppler / poppler-cpp / poppler-cpp-devel / poppler-demos / etc");
}
