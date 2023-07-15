#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2589 and 
# CentOS Errata and Security Advisory 2016:2589 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(95335);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-4994");
  script_xref(name:"RHSA", value:"2016:2589");

  script_name(english:"CentOS 7 : gimp / gimp-help (CESA-2016:2589)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for gimp and gimp-help is now available for Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The GIMP (GNU Image Manipulation Program) is an image composition and
editing program. GIMP provides a large image manipulation toolbox,
including channel operations and layers, effects, sub-pixel imaging
and anti-aliasing, and conversions, all with multi-level undo.

The following packages have been upgraded to a newer upstream version:
gimp (2.8.16), gimp-help (2.8.2). (BZ#1298226, BZ#1370595)

Security Fix(es) :

* Multiple use-after-free vulnerabilities were found in GIMP in the
channel and layer properties parsing process when loading XCF files.
An attacker could create a specially crafted XCF file which could
cause GIMP to crash. (CVE-2016-4994)

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.3 Release Notes linked from the References section."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2016-November/003202.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?695a0f40"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2016-November/003594.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?76d84759"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gimp and / or gimp-help packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-4994");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp-devel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp-help");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp-help-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp-help-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp-help-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp-help-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp-help-en_GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp-help-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp-help-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp-help-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp-help-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp-help-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp-help-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp-help-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp-help-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp-help-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp-help-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp-help-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp-help-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gimp-2.8.16-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gimp-devel-2.8.16-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gimp-devel-tools-2.8.16-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gimp-help-2.8.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gimp-help-ca-2.8.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gimp-help-da-2.8.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gimp-help-de-2.8.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gimp-help-el-2.8.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gimp-help-en_GB-2.8.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gimp-help-es-2.8.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gimp-help-fr-2.8.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gimp-help-it-2.8.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gimp-help-ja-2.8.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gimp-help-ko-2.8.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gimp-help-nl-2.8.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gimp-help-nn-2.8.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gimp-help-pt_BR-2.8.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gimp-help-ru-2.8.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gimp-help-sl-2.8.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gimp-help-sv-2.8.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gimp-help-zh_CN-2.8.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gimp-libs-2.8.16-3.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gimp / gimp-devel / gimp-devel-tools / gimp-help / gimp-help-ca / etc");
}
