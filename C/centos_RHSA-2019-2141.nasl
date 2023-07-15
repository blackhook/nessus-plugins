#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:2141 and 
# CentOS Errata and Security Advisory 2019:2141 respectively.
#

include("compat.inc");

if (description)
{
  script_id(128362);
  script_version("1.3");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2018-6790");
  script_xref(name:"RHSA", value:"2019:2141");

  script_name(english:"CentOS 7 : kde-settings / kde-workspace / kdelibs / kmag / virtuoso-opensource (CESA-2019:2141)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for kde-workspace, kde-settings, kdelibs, kmag, and
virtuoso-opensource is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Low. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link (s) in the References section.

The K Desktop Environment (KDE) is a graphical desktop environment for
the X Window System. The kdelibs packages include core libraries for
the K Desktop Environment.

The kde-workspace packages consist of components providing the KDE
graphical desktop environment.

Security Fix(es) :

* kde-workspace: Missing sanitization of notifications allows to leak
client IP address via IMG element (CVE-2018-6790)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.7 Release Notes linked from the References section."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/005925.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0ed4c873"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/005926.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8dc65282"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/005927.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?459daa4c"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/005931.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3fd23ca6"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/006178.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0d610d3e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6790");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kcm_colors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kde-settings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kde-settings-ksplash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kde-settings-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kde-settings-plasma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kde-settings-pulseaudio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kde-style-oxygen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kde-workspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kde-workspace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kde-workspace-ksplash-themes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kde-workspace-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdeclassic-cursor-theme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdelibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdelibs-apidocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdelibs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdelibs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdelibs-ktexteditor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kgreeter-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:khotkeys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:khotkeys-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kinfocenter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kmag");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kmenuedit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ksysguard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ksysguard-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ksysguardd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kwin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kwin-gles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kwin-gles-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kwin-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libkworkspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:oxygen-cursor-themes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:plasma-scriptengine-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:plasma-scriptengine-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt-settings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:virtuoso-opensource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:virtuoso-opensource-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/30");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kcm_colors-4.11.19-13.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kde-settings-19-23.9.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kde-settings-ksplash-19-23.9.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kde-settings-minimal-19-23.9.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kde-settings-plasma-19-23.9.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kde-settings-pulseaudio-19-23.9.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kde-style-oxygen-4.11.19-13.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kde-workspace-4.11.19-13.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kde-workspace-devel-4.11.19-13.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kde-workspace-ksplash-themes-4.11.19-13.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kde-workspace-libs-4.11.19-13.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kdeclassic-cursor-theme-4.11.19-13.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kdelibs-4.14.8-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kdelibs-apidocs-4.14.8-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kdelibs-common-4.14.8-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kdelibs-devel-4.14.8-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kdelibs-ktexteditor-4.14.8-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kgreeter-plugins-4.11.19-13.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"khotkeys-4.11.19-13.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"khotkeys-libs-4.11.19-13.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kinfocenter-4.11.19-13.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kmag-4.10.5-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kmenuedit-4.11.19-13.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ksysguard-4.11.19-13.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ksysguard-libs-4.11.19-13.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ksysguardd-4.11.19-13.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kwin-4.11.19-13.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kwin-gles-4.11.19-13.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kwin-gles-libs-4.11.19-13.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kwin-libs-4.11.19-13.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libkworkspace-4.11.19-13.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"oxygen-cursor-themes-4.11.19-13.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"plasma-scriptengine-python-4.11.19-13.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"plasma-scriptengine-ruby-4.11.19-13.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt-settings-19-23.9.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"virtuoso-opensource-6.1.6-7.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"virtuoso-opensource-utils-6.1.6-7.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kcm_colors / kde-settings / kde-settings-ksplash / etc");
}
