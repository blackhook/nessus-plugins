#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(128258);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/24");

  script_cve_id("CVE-2018-15518", "CVE-2018-19869", "CVE-2018-19870", "CVE-2018-19871", "CVE-2018-19873");

  script_name(english:"Scientific Linux Security Update : qt5 on SL7.x x86_64 (20190806)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The following packages have been upgraded to a later upstream version:
qt5-qt3d (5.9.7), qt5-qtbase (5.9.7), qt5-qtcanvas3d (5.9.7),
qt5-qtconnectivity (5.9.7), qt5-qtdeclarative (5.9.7), qt5-qtdoc
(5.9.7), qt5-qtgraphicaleffects (5.9.7), qt5-qtimageformats (5.9.7),
qt5-qtlocation (5.9.7), qt5-qtmultimedia (5.9.7), qt5-qtquickcontrols
(5.9.7), qt5-qtquickcontrols2 (5.9.7), qt5-qtscript (5.9.7),
qt5-qtsensors (5.9.7), qt5-qtserialbus (5.9.7), qt5-qtserialport
(5.9.7), qt5-qtsvg (5.9.7), qt5-qttools (5.9.7), qt5-qttranslations
(5.9.7), qt5-qtwayland (5.9.7), qt5-qtwebchannel (5.9.7),
qt5-qtwebsockets (5.9.7), qt5-qtx11extras (5.9.7), qt5-qtxmlpatterns
(5.9.7).

Security Fix(es) :

  - qt5-qtbase: Double free in QXmlStreamReader
    (CVE-2018-15518)

  - qt5-qtsvg: Invalid parsing of malformed url reference
    resulting in a denial of service (CVE-2018-19869)

  - qt5-qtbase: QImage allocation failure in qgifhandler
    (CVE-2018-19870)

  - qt5-qtimageformats: QTgaFile CPU exhaustion
    (CVE-2018-19871)

  - qt5-qtbase: QBmpHandler segmentation fault on malformed
    BMP file (CVE-2018-19873)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1908&L=SCIENTIFIC-LINUX-ERRATA&P=19876
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b1d81f52"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-assistant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-designer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-doctools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-linguist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qdbusviewer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qt3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qt3d-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qt3d-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qt3d-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qt3d-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtbase-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtbase-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtbase-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtbase-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtbase-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtbase-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtbase-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtbase-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtbase-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtbase-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtcanvas3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtcanvas3d-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtcanvas3d-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtcanvas3d-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtconnectivity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtconnectivity-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtconnectivity-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtconnectivity-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtconnectivity-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtdeclarative");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtdeclarative-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtdeclarative-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtdeclarative-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtdeclarative-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtdeclarative-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtgraphicaleffects");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtgraphicaleffects-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtgraphicaleffects-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtimageformats");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtimageformats-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtimageformats-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtlocation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtlocation-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtlocation-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtlocation-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtlocation-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtmultimedia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtmultimedia-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtmultimedia-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtmultimedia-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtmultimedia-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtquickcontrols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtquickcontrols-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtquickcontrols-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtquickcontrols-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtquickcontrols2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtquickcontrols2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtquickcontrols2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtquickcontrols2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtquickcontrols2-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtscript-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtscript-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtscript-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtsensors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtsensors-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtsensors-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtsensors-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtsensors-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtserialbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtserialbus-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtserialbus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtserialbus-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtserialbus-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtserialport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtserialport-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtserialport-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtserialport-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtserialport-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtsvg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtsvg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtsvg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtsvg-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtsvg-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qttools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qttools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qttools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qttools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qttools-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qttools-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qttools-libs-designer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qttools-libs-designercomponents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qttools-libs-help");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qttools-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qttranslations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtwayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtwayland-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtwayland-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtwayland-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtwayland-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtwebchannel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtwebchannel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtwebchannel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtwebchannel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtwebchannel-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtwebsockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtwebsockets-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtwebsockets-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtwebsockets-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtwebsockets-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtx11extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtx11extras-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtx11extras-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtx11extras-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtxmlpatterns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtxmlpatterns-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtxmlpatterns-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtxmlpatterns-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-qtxmlpatterns-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt5-rpm-macros");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-assistant-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-designer-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-doctools-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-linguist-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qdbusviewer-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qt3d-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qt3d-debuginfo-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qt3d-devel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"qt5-qt3d-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qt3d-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qt3d-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtbase-5.9.7-2.el7")) flag++;
if (rpm_check(release:"SL7", reference:"qt5-qtbase-common-5.9.7-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtbase-common-5.9.7-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtbase-debuginfo-5.9.7-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtbase-devel-5.9.7-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtbase-doc-5.9.7-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtbase-examples-5.9.7-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtbase-gui-5.9.7-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtbase-mysql-5.9.7-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtbase-odbc-5.9.7-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtbase-postgresql-5.9.7-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtbase-static-5.9.7-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtcanvas3d-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtcanvas3d-debuginfo-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"qt5-qtcanvas3d-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtcanvas3d-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtcanvas3d-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtconnectivity-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtconnectivity-debuginfo-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtconnectivity-devel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"qt5-qtconnectivity-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtconnectivity-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtconnectivity-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtdeclarative-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtdeclarative-debuginfo-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtdeclarative-devel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtdeclarative-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtdeclarative-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtdeclarative-static-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"qt5-qtdoc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtdoc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtgraphicaleffects-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtgraphicaleffects-debuginfo-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"qt5-qtgraphicaleffects-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtgraphicaleffects-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtimageformats-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtimageformats-debuginfo-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"qt5-qtimageformats-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtimageformats-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtlocation-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtlocation-debuginfo-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtlocation-devel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"qt5-qtlocation-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtlocation-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtlocation-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtmultimedia-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtmultimedia-debuginfo-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtmultimedia-devel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"qt5-qtmultimedia-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtmultimedia-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtmultimedia-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtquickcontrols-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtquickcontrols-debuginfo-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"qt5-qtquickcontrols-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtquickcontrols-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtquickcontrols-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtquickcontrols2-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtquickcontrols2-debuginfo-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtquickcontrols2-devel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtquickcontrols2-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtquickcontrols2-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtscript-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtscript-debuginfo-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtscript-devel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"qt5-qtscript-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtscript-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtscript-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtsensors-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtsensors-debuginfo-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtsensors-devel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"qt5-qtsensors-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtsensors-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtsensors-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtserialbus-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtserialbus-debuginfo-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtserialbus-devel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"qt5-qtserialbus-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtserialbus-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtserialbus-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtserialport-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtserialport-debuginfo-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtserialport-devel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"qt5-qtserialport-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtserialport-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtserialport-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtsvg-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtsvg-debuginfo-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtsvg-devel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"qt5-qtsvg-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtsvg-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtsvg-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qttools-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"qt5-qttools-common-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qttools-common-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qttools-debuginfo-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qttools-devel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"qt5-qttools-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qttools-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qttools-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qttools-libs-designer-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qttools-libs-designercomponents-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qttools-libs-help-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qttools-static-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"qt5-qttranslations-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qttranslations-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtwayland-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtwayland-debuginfo-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtwayland-devel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"qt5-qtwayland-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtwayland-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtwayland-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtwebchannel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtwebchannel-debuginfo-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtwebchannel-devel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"qt5-qtwebchannel-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtwebchannel-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtwebchannel-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtwebsockets-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtwebsockets-debuginfo-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtwebsockets-devel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"qt5-qtwebsockets-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtwebsockets-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtwebsockets-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtx11extras-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtx11extras-debuginfo-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtx11extras-devel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"qt5-qtx11extras-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtx11extras-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtxmlpatterns-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtxmlpatterns-debuginfo-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtxmlpatterns-devel-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"qt5-qtxmlpatterns-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtxmlpatterns-doc-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-qtxmlpatterns-examples-5.9.7-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"qt5-rpm-macros-5.9.7-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt5-rpm-macros-5.9.7-2.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qt5-assistant / qt5-designer / qt5-doctools / qt5-linguist / etc");
}
