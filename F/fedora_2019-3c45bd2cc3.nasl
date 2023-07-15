#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-3c45bd2cc3.
#

include("compat.inc");

if (description)
{
  script_id(121444);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/20");

  script_cve_id("CVE-2018-15518", "CVE-2018-19869", "CVE-2018-19871");
  script_xref(name:"FEDORA", value:"2019-3c45bd2cc3");

  script_name(english:"Fedora 29 : mingw-python-qt5 / mingw-qt5-qt3d / mingw-qt5-qtactiveqt / etc (2019-3c45bd2cc3)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to mingw-qt5-*-5.11.3, see
http://blog.qt.io/blog/2018/12/04/qt-5-11-3-released-important-securit
y-updates/ for details. Update to mingw-sip-4.19.13, see
https://www.riverbankcomputing.com/static/Downloads/sip/ChangeLog for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  # http://blog.qt.io/blog/2018/12/04/qt-5-11-3-released-important-security-updates/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?98ae98d6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-3c45bd2cc3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.riverbankcomputing.com/static/Downloads/sip/ChangeLog"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-python-qt5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-qt5-qt3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-qt5-qtactiveqt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-qt5-qtbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-qt5-qtcharts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-qt5-qtdeclarative");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-qt5-qtgraphicaleffects");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-qt5-qtimageformats");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-qt5-qtlocation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-qt5-qtmultimedia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-qt5-qtquickcontrols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-qt5-qtscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-qt5-qtsensors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-qt5-qtserialport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-qt5-qtsvg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-qt5-qttools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-qt5-qttranslations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-qt5-qtwebkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-qt5-qtwebsockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-qt5-qtwinextras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-qt5-qtxmlpatterns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-sip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:29");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^29([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 29", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC29", reference:"mingw-python-qt5-5.11.3-2.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"mingw-qt5-qt3d-5.11.3-1.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"mingw-qt5-qtactiveqt-5.11.3-1.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"mingw-qt5-qtbase-5.11.3-1.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"mingw-qt5-qtcharts-5.11.3-1.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"mingw-qt5-qtdeclarative-5.11.3-1.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"mingw-qt5-qtgraphicaleffects-5.11.3-1.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"mingw-qt5-qtimageformats-5.11.3-1.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"mingw-qt5-qtlocation-5.11.3-1.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"mingw-qt5-qtmultimedia-5.11.3-1.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"mingw-qt5-qtquickcontrols-5.11.3-1.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"mingw-qt5-qtscript-5.11.3-1.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"mingw-qt5-qtsensors-5.11.3-1.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"mingw-qt5-qtserialport-5.11.3-1.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"mingw-qt5-qtsvg-5.11.3-1.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"mingw-qt5-qttools-5.11.3-1.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"mingw-qt5-qttranslations-5.11.3-1.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"mingw-qt5-qtwebkit-5.9.4-0.8.gitbd0657f.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"mingw-qt5-qtwebsockets-5.11.3-1.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"mingw-qt5-qtwinextras-5.11.3-1.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"mingw-qt5-qtxmlpatterns-5.11.3-1.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"mingw-sip-4.19.13-2.fc29")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mingw-python-qt5 / mingw-qt5-qt3d / mingw-qt5-qtactiveqt / etc");
}
