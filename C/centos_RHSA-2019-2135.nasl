#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:2135 and 
# CentOS Errata and Security Advisory 2019:2135 respectively.
#

include("compat.inc");

if (description)
{
  script_id(128359);
  script_version("1.3");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2018-15518", "CVE-2018-19869", "CVE-2018-19870", "CVE-2018-19871", "CVE-2018-19873");
  script_xref(name:"RHSA", value:"2019:2135");

  script_name(english:"CentOS 7 : qt5-qt3d / qt5-qtbase / qt5-qtcanvas3d / qt5-qtconnectivity / qt5-qtdeclarative / etc (CESA-2019:2135)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Qt is a software toolkit for developing applications. The qt5-base
packages contain base tools for string, xml, and network handling in
Qt.

The following packages have been upgraded to a later upstream version:
qt5-qt3d (5.9.7), qt5-qtbase (5.9.7), qt5-qtcanvas3d (5.9.7),
qt5-qtconnectivity (5.9.7), qt5-qtdeclarative (5.9.7), qt5-qtdoc
(5.9.7), qt5-qtgraphicaleffects (5.9.7), qt5-qtimageformats (5.9.7),
qt5-qtlocation (5.9.7), qt5-qtmultimedia (5.9.7), qt5-qtquickcontrols
(5.9.7), qt5-qtquickcontrols2 (5.9.7), qt5-qtscript (5.9.7),
qt5-qtsensors (5.9.7), qt5-qtserialbus (5.9.7), qt5-qtserialport
(5.9.7), qt5-qtsvg (5.9.7), qt5-qttools (5.9.7), qt5-qttranslations
(5.9.7), qt5-qtwayland (5.9.7), qt5-qtwebchannel (5.9.7),
qt5-qtwebsockets (5.9.7), qt5-qtx11extras (5.9.7), qt5-qtxmlpatterns
(5.9.7). (BZ#1564000, BZ#1564001, BZ#1564002, BZ#1564003, BZ#1564004,
BZ#1564006, BZ# 1564007, BZ#1564008, BZ#1564009, BZ#1564010,
BZ#1564011, BZ#1564012, BZ# 1564013, BZ#1564014, BZ#1564015,
BZ#1564016, BZ#1564017, BZ#1564018, BZ# 1564019, BZ#1564020,
BZ#1564021, BZ#1564022, BZ#1564023, BZ#1564024)

Security Fix(es) :

* qt5-qtbase: Double free in QXmlStreamReader (CVE-2018-15518)

* qt5-qtsvg: Invalid parsing of malformed url reference resulting in a
denial of service (CVE-2018-19869)

* qt5-qtbase: QImage allocation failure in qgifhandler
(CVE-2018-19870)

* qt5-qtimageformats: QTgaFile CPU exhaustion (CVE-2018-19871)

* qt5-qtbase: QBmpHandler segmentation fault on malformed BMP file
(CVE-2018-19873)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.7 Release Notes linked from the References section."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/006082.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cf56f728"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/006083.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5727a200"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/006084.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aabd21d6"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/006085.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9330f2cf"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/006086.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bdf74c91"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/006087.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7d6c971b"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/006088.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f86c2d09"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/006089.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?454a41b6"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/006090.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1c1c5365"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/006091.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c3782cd4"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/006092.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5623576d"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/006093.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7211c3a9"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/006094.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?57f30089"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/006095.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?26d7e0e8"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/006096.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?105fea91"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/006097.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f3ad8483"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/006098.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ce89c712"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/006099.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?edda3ff8"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/006100.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7c905578"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/006101.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ddcd928"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/006102.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fdbd8efb"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/006108.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?06c1b723"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/006109.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?37932487"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/006110.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?762704d9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19873");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-assistant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-designer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-doctools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-linguist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qdbusviewer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qt3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qt3d-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qt3d-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qt3d-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtbase-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtbase-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtbase-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtbase-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtbase-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtbase-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtbase-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtbase-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtbase-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtcanvas3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtcanvas3d-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtcanvas3d-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtconnectivity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtconnectivity-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtconnectivity-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtconnectivity-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtdeclarative");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtdeclarative-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtdeclarative-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtdeclarative-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtdeclarative-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtgraphicaleffects");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtgraphicaleffects-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtimageformats");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtimageformats-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtlocation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtlocation-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtlocation-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtlocation-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtmultimedia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtmultimedia-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtmultimedia-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtmultimedia-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtquickcontrols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtquickcontrols-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtquickcontrols-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtquickcontrols2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtquickcontrols2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtquickcontrols2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtquickcontrols2-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtscript-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtscript-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtsensors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtsensors-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtsensors-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtsensors-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtserialbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtserialbus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtserialbus-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtserialbus-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtserialport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtserialport-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtserialport-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtserialport-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtsvg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtsvg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtsvg-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtsvg-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qttools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qttools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qttools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qttools-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qttools-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qttools-libs-designer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qttools-libs-designercomponents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qttools-libs-help");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qttools-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qttranslations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtwayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtwayland-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtwayland-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtwayland-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtwebchannel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtwebchannel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtwebchannel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtwebchannel-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtwebsockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtwebsockets-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtwebsockets-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtwebsockets-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtx11extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtx11extras-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtx11extras-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtxmlpatterns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtxmlpatterns-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtxmlpatterns-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtxmlpatterns-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-rpm-macros");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/26");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-assistant-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-designer-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-doctools-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-linguist-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qdbusviewer-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qt3d-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qt3d-devel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qt3d-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qt3d-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtbase-5.9.7-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtbase-common-5.9.7-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtbase-devel-5.9.7-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtbase-doc-5.9.7-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtbase-examples-5.9.7-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtbase-gui-5.9.7-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtbase-mysql-5.9.7-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtbase-odbc-5.9.7-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtbase-postgresql-5.9.7-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtbase-static-5.9.7-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtcanvas3d-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtcanvas3d-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtcanvas3d-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtconnectivity-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtconnectivity-devel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtconnectivity-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtconnectivity-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtdeclarative-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtdeclarative-devel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtdeclarative-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtdeclarative-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtdeclarative-static-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtdoc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtgraphicaleffects-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtgraphicaleffects-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtimageformats-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtimageformats-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtlocation-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtlocation-devel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtlocation-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtlocation-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtmultimedia-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtmultimedia-devel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtmultimedia-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtmultimedia-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtquickcontrols-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtquickcontrols-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtquickcontrols-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtquickcontrols2-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtquickcontrols2-devel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtquickcontrols2-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtquickcontrols2-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtscript-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtscript-devel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtscript-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtscript-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtsensors-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtsensors-devel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtsensors-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtsensors-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtserialbus-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtserialbus-devel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtserialbus-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtserialbus-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtserialport-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtserialport-devel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtserialport-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtserialport-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtsvg-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtsvg-devel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtsvg-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtsvg-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qttools-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qttools-common-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qttools-devel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qttools-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qttools-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qttools-libs-designer-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qttools-libs-designercomponents-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qttools-libs-help-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qttools-static-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qttranslations-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtwayland-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtwayland-devel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtwayland-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtwayland-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtwebchannel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtwebchannel-devel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtwebchannel-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtwebchannel-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtwebsockets-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtwebsockets-devel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtwebsockets-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtwebsockets-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtx11extras-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtx11extras-devel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtx11extras-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtxmlpatterns-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtxmlpatterns-devel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtxmlpatterns-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-qtxmlpatterns-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qt5-rpm-macros-5.9.7-2.el7")) flag++;


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
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qt5-assistant / qt5-designer / qt5-doctools / qt5-linguist / etc");
}
