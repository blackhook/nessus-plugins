#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-c0d3db441f.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(107035);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2017-15407", "CVE-2017-15409", "CVE-2017-15410", "CVE-2017-15411", "CVE-2017-15415", "CVE-2017-15416", "CVE-2017-15418", "CVE-2017-15419", "CVE-2017-15422", "CVE-2017-15423", "CVE-2017-15424", "CVE-2017-15425", "CVE-2017-15426", "CVE-2018-6031", "CVE-2018-6033", "CVE-2018-6034", "CVE-2018-6036", "CVE-2018-6037", "CVE-2018-6038", "CVE-2018-6040", "CVE-2018-6041", "CVE-2018-6042", "CVE-2018-6047", "CVE-2018-6048", "CVE-2018-6050", "CVE-2018-6051", "CVE-2018-6052", "CVE-2018-6053", "CVE-2018-6054");
  script_xref(name:"FEDORA", value:"2018-c0d3db441f");

  script_name(english:"Fedora 26 : qt5-qtwebengine (2018-c0d3db441f)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update updates QtWebEngine to the 5.10.1 bugfix and security
release. QtWebEngine 5.10.1 is part of the Qt 5.10.1 release, but only
the QtWebEngine component is included in this update.

This update includes :

  - Security fixes from Chromium up to version
    64.0.3282.140. Including: CVE-2017-15407,
    CVE-2017-15409, CVE-2017-15410, CVE-2017-15411,
    CVE-2017-15415, CVE-2017-15416, CVE-2017-15418,
    CVE-2017-15419, CVE-2017-15422, CVE-2017-15423,
    CVE-2017-15424, CVE-2017-15425, CVE-2017-15426,
    CVE-2018-6031, CVE-2018-6033, CVE-2018-6034,
    CVE-2018-6036, CVE-2018-6037, CVE-2018-6038,
    CVE-2018-6040, CVE-2018-6041, CVE-2018-6042,
    CVE-2018-6047, CVE-2018-6048, CVE-2018-6050,
    CVE-2018-6051, CVE-2018-6052, CVE-2018-6053 and
    CVE-2018-6054.

  - Mitigations for SPECTRE: disabled shared-buffers, added
    cryptographic noise to precision timers

  - [QTBUG-47206] Fixed incorrect layouting due to bug in
    HTML5 viewport support.

  - [QTBUG-47945, QTBUG-65647] Fixed random crashes on exit

  - [QTBUG-57206] Fixed regression in viewport handling in
    embedded mode

  - [QTBUG-58400] Improved memory usage when printing

  - [QTBUG-63867] Fixed <canvas> elements when compiled
    without OpenGL

  - [QTBUG-63266, QTBUG-64436] Fixed that pointerType of
    Pointer Events was empty

  - [QTBUG-63606] Improved runtime disabling and clearing of
    HTTP cache

  - [QTBUG-64436] QtWebEngineWidgets: Fixed crash when
    exiting fullscreen mode using the context menu.

  - [QTBUG-64560] Fixed rendering glitches after
    renderProcessTerminated signal was emitted.

  - [QTBUG-64812] Fixed message bubble position in Hi-DPI
    mode

  - [QTBUG-64869, QTBUG-65004] Added testing for 32-bit host
    compiler when crossbuilding to 32-bit platforms

  - [QTBUG-64933] QtWebEngineWidgets: Fixed tooltips that
    did still show after mouse was moved away.

  - [QTBUG-65239] Fixed hanging of process if application is
    closed too fast after startup.

  - [QTBUG-65715] Fixed double margins when printing

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-c0d3db441f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected qt5-qtwebengine package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtwebengine");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:26");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^26([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 26", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC26", reference:"qt5-qtwebengine-5.10.1-1.fc26")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qt5-qtwebengine");
}
