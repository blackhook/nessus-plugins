#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:0849 and 
# CentOS Errata and Security Advisory 2018:0849 respectively.
#

include("compat.inc");

if (description)
{
  script_id(109374);
  script_version("1.6");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2017-11671");
  script_xref(name:"RHSA", value:"2018:0849");

  script_name(english:"CentOS 7 : gcc (CESA-2018:0849)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for gcc is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Low. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link (s) in the References section.

The gcc packages provide compilers for C, C++, Java, Fortran,
Objective C, and Ada 95 GNU, as well as related support libraries.

Security Fix(es) :

* gcc: GCC generates incorrect code for RDRAND/RDSEED intrinsics
(CVE-2017-11671)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.5 Release Notes linked from the References section."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-April/004803.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0c3a52de"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gcc packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11671");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcc-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcc-gfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcc-gnat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcc-go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcc-objc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcc-objc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcc-plugin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libasan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libasan-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libatomic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libatomic-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgfortran-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgnat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgnat-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgnat-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgo-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgo-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgomp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libitm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libitm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libitm-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libmudflap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libmudflap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libmudflap-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libobjc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libquadmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libquadmath-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libquadmath-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libstdc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libstdc++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libstdc++-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libstdc++-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtsan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtsan-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"cpp-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gcc-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gcc-c++-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gcc-gfortran-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gcc-gnat-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gcc-go-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gcc-objc-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gcc-objc++-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gcc-plugin-devel-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libasan-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libasan-static-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libatomic-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libatomic-static-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgcc-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgfortran-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgfortran-static-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgnat-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgnat-devel-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgnat-static-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgo-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgo-devel-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgo-static-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgomp-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libitm-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libitm-devel-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libitm-static-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libmudflap-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libmudflap-devel-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libmudflap-static-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libobjc-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libquadmath-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libquadmath-devel-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libquadmath-static-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libstdc++-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libstdc++-devel-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libstdc++-docs-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libstdc++-static-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libtsan-4.8.5-28.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libtsan-static-4.8.5-28.el7")) flag++;


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
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cpp / gcc / gcc-c++ / gcc-gfortran / gcc-gnat / gcc-go / gcc-objc / etc");
}
