#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-e83c26a8c9.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101740);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2017-5006", "CVE-2017-5007", "CVE-2017-5008", "CVE-2017-5009", "CVE-2017-5010", "CVE-2017-5011", "CVE-2017-5012", "CVE-2017-5013", "CVE-2017-5014", "CVE-2017-5015", "CVE-2017-5016", "CVE-2017-5017", "CVE-2017-5018", "CVE-2017-5019", "CVE-2017-5020", "CVE-2017-5021", "CVE-2017-5022", "CVE-2017-5023", "CVE-2017-5024", "CVE-2017-5025", "CVE-2017-5026", "CVE-2017-5027", "CVE-2017-5029", "CVE-2017-5032", "CVE-2017-5033", "CVE-2017-5034", "CVE-2017-5036", "CVE-2017-5039", "CVE-2017-5040", "CVE-2017-5044", "CVE-2017-5045", "CVE-2017-5046", "CVE-2017-5052", "CVE-2017-5053", "CVE-2017-5055", "CVE-2017-5057", "CVE-2017-5058", "CVE-2017-5059", "CVE-2017-5060", "CVE-2017-5061", "CVE-2017-5062", "CVE-2017-5065", "CVE-2017-5066", "CVE-2017-5067", "CVE-2017-5068", "CVE-2017-5069");
  script_xref(name:"FEDORA", value:"2017-e83c26a8c9");

  script_name(english:"Fedora 26 : qt5-qtwebengine (2017-e83c26a8c9)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update updates QtWebEngine to the 5.9.0 release. QtWebEngine
5.9.0 is part of the Qt 5.9.0 release, but only the QtWebEngine
component is included in this update.

The update fixes the following security issues in QtWebEngine 5.8.0:
CVE-2017-5006, CVE-2017-5007, CVE-2017-5008, CVE-2017-5009,
CVE-2017-5010, CVE-2017-5011, CVE-2017-5012, CVE-2017-5013,
CVE-2017-5014, CVE-2017-5015, CVE-2017-5016, CVE-2017-5017,
CVE-2017-5018, CVE-2017-5019, CVE-2017-5020, CVE-2017-5021,
CVE-2017-5022, CVE-2017-5023, CVE-2017-5024, CVE-2017-5025,
CVE-2017-5026, CVE-2017-5027, CVE-2017-5029, CVE-2017-5032,
CVE-2017-5033, CVE-2017-5034, CVE-2017-5036, CVE-2017-5039,
CVE-2017-5040, CVE-2017-5044, CVE-2017-5045, CVE-2017-5046,
CVE-2017-5052, CVE-2017-5053, CVE-2017-5055, CVE-2017-5057,
CVE-2017-5058, CVE-2017-5059, CVE-2017-5060, CVE-2017-5061,
CVE-2017-5062, CVE-2017-5065, CVE-2017-5066, CVE-2017-5067,
CVE-2017-5068, and CVE-2017-5069.

Other important changes include :

  - Based on Chromium 56.0.2924.122 with security fixes from
    Chromium up to version 58.0.3029.96. (5.8.0 was based on
    Chromium 53.0.2785.148 with security fixes from Chromium
    up to version 55.0.2883.75.)

  - [QTBUG-54650, QTBUG-59922] Accessibility is now disabled
    by default on Linux, like it is in Chrome, due to poor
    options for enabling it conditionally and its heavy
    performance impact. Set the environment variable
    `QTWEBENGINE_ENABLE_LINUX_ACCESSIBILITY` to enable it
    again.

  - [QTBUG-56531] Enabled `filesystem:` protocol handler.

  - [QTBUG-57720] Optimized incremental scene-graph
    rendering in particular for software rendering.

  - [QTBUG-60049] Enabled brotli support.

  - Many bug fixes, see
    https://code.qt.io/cgit/qt/qtwebengine.git/tree/dist/cha
    nges-5.9.0?h=5.9 for details.

In addition, this build includes a fix for
https://bugreports.qt.io/browse/QTBUG-61521 , a binary incompatibility
in QtWebEngine 5.9.0 compared to 5.8.0.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-e83c26a8c9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugreports.qt.io/browse/QTBUG-61521"
  );
  # https://code.qt.io/cgit/qt/qtwebengine.git/tree/dist/changes-5.9.0?h=5.9
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d3ac68dd"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected qt5-qtwebengine package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtwebengine");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:26");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"FC26", reference:"qt5-qtwebengine-5.9.0-4.fc26")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qt5-qtwebengine");
}
