##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:1665. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(136117);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id("CVE-2018-19869", "CVE-2018-19871", "CVE-2018-19872");
  script_bugtraq_id(106338);
  script_xref(name:"RHSA", value:"2020:1665");

  script_name(english:"RHEL 8 : qt5 (RHSA-2020:1665)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:1665 advisory.

  - qt5-qtsvg: Invalid parsing of malformed url reference resulting in a denial of service (CVE-2018-19869)

  - qt5-qtimageformats: QTgaFile CPU exhaustion (CVE-2018-19871)

  - qt: Malformed PPM image causing division by zero and crash in qppmhandler.cpp (CVE-2018-19872)

  - qt5-qtbase: Out-of-bounds access in generateDirectionalRuns() function in qtextengine.cpp (CVE-2019-18281)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-19869");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-19871");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-19872");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-18281");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:1665");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1661460");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1661465");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1691636");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1764742");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19872");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-19871");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 369, 400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-qt5-rpm-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-pyqt5-sip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-qt5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-qt5-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-qt5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-sip-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qgnomeplatform");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-assistant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-designer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-doctools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-linguist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qdbusviewer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qt3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qt3d-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qt3d-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtbase-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtbase-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtbase-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtbase-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtbase-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtbase-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtbase-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtbase-private-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtbase-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtcanvas3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtcanvas3d-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtconnectivity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtconnectivity-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtconnectivity-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtdeclarative");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtdeclarative-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtdeclarative-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtdeclarative-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtgraphicaleffects");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtimageformats");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtlocation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtlocation-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtlocation-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtmultimedia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtmultimedia-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtmultimedia-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtquickcontrols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtquickcontrols-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtquickcontrols2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtquickcontrols2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtquickcontrols2-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtscript-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtsensors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtsensors-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtsensors-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtserialbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtserialbus-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtserialport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtserialport-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtserialport-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtsvg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtsvg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtsvg-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qttools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qttools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qttools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qttools-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qttools-libs-designer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qttools-libs-designercomponents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qttools-libs-help");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qttools-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qttranslations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtwayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtwayland-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtwayland-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtwebchannel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtwebchannel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtwebchannel-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtwebsockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtwebsockets-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtwebsockets-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtx11extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtx11extras-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtxmlpatterns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtxmlpatterns-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtxmlpatterns-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-rpm-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-srpm-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sip");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel8/8.2/x86_64/appstream/debug',
      'content/aus/rhel8/8.2/x86_64/appstream/os',
      'content/aus/rhel8/8.2/x86_64/appstream/source/SRPMS',
      'content/aus/rhel8/8.2/x86_64/baseos/debug',
      'content/aus/rhel8/8.2/x86_64/baseos/os',
      'content/aus/rhel8/8.2/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.2/ppc64le/appstream/debug',
      'content/e4s/rhel8/8.2/ppc64le/appstream/os',
      'content/e4s/rhel8/8.2/ppc64le/appstream/source/SRPMS',
      'content/e4s/rhel8/8.2/ppc64le/baseos/debug',
      'content/e4s/rhel8/8.2/ppc64le/baseos/os',
      'content/e4s/rhel8/8.2/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel8/8.2/ppc64le/highavailability/debug',
      'content/e4s/rhel8/8.2/ppc64le/highavailability/os',
      'content/e4s/rhel8/8.2/ppc64le/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.2/ppc64le/sap-solutions/debug',
      'content/e4s/rhel8/8.2/ppc64le/sap-solutions/os',
      'content/e4s/rhel8/8.2/ppc64le/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.2/ppc64le/sap/debug',
      'content/e4s/rhel8/8.2/ppc64le/sap/os',
      'content/e4s/rhel8/8.2/ppc64le/sap/source/SRPMS',
      'content/e4s/rhel8/8.2/x86_64/appstream/debug',
      'content/e4s/rhel8/8.2/x86_64/appstream/os',
      'content/e4s/rhel8/8.2/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel8/8.2/x86_64/baseos/debug',
      'content/e4s/rhel8/8.2/x86_64/baseos/os',
      'content/e4s/rhel8/8.2/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.2/x86_64/highavailability/debug',
      'content/e4s/rhel8/8.2/x86_64/highavailability/os',
      'content/e4s/rhel8/8.2/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.2/x86_64/sap-solutions/debug',
      'content/e4s/rhel8/8.2/x86_64/sap-solutions/os',
      'content/e4s/rhel8/8.2/x86_64/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.2/x86_64/sap/debug',
      'content/e4s/rhel8/8.2/x86_64/sap/os',
      'content/e4s/rhel8/8.2/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.2/aarch64/appstream/debug',
      'content/eus/rhel8/8.2/aarch64/appstream/os',
      'content/eus/rhel8/8.2/aarch64/appstream/source/SRPMS',
      'content/eus/rhel8/8.2/aarch64/baseos/debug',
      'content/eus/rhel8/8.2/aarch64/baseos/os',
      'content/eus/rhel8/8.2/aarch64/baseos/source/SRPMS',
      'content/eus/rhel8/8.2/aarch64/codeready-builder/debug',
      'content/eus/rhel8/8.2/aarch64/codeready-builder/os',
      'content/eus/rhel8/8.2/aarch64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.2/aarch64/highavailability/debug',
      'content/eus/rhel8/8.2/aarch64/highavailability/os',
      'content/eus/rhel8/8.2/aarch64/highavailability/source/SRPMS',
      'content/eus/rhel8/8.2/aarch64/supplementary/debug',
      'content/eus/rhel8/8.2/aarch64/supplementary/os',
      'content/eus/rhel8/8.2/aarch64/supplementary/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/appstream/debug',
      'content/eus/rhel8/8.2/ppc64le/appstream/os',
      'content/eus/rhel8/8.2/ppc64le/appstream/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/baseos/debug',
      'content/eus/rhel8/8.2/ppc64le/baseos/os',
      'content/eus/rhel8/8.2/ppc64le/baseos/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/codeready-builder/debug',
      'content/eus/rhel8/8.2/ppc64le/codeready-builder/os',
      'content/eus/rhel8/8.2/ppc64le/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/highavailability/debug',
      'content/eus/rhel8/8.2/ppc64le/highavailability/os',
      'content/eus/rhel8/8.2/ppc64le/highavailability/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/resilientstorage/debug',
      'content/eus/rhel8/8.2/ppc64le/resilientstorage/os',
      'content/eus/rhel8/8.2/ppc64le/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/sap-solutions/debug',
      'content/eus/rhel8/8.2/ppc64le/sap-solutions/os',
      'content/eus/rhel8/8.2/ppc64le/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/sap/debug',
      'content/eus/rhel8/8.2/ppc64le/sap/os',
      'content/eus/rhel8/8.2/ppc64le/sap/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/supplementary/debug',
      'content/eus/rhel8/8.2/ppc64le/supplementary/os',
      'content/eus/rhel8/8.2/ppc64le/supplementary/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/appstream/debug',
      'content/eus/rhel8/8.2/x86_64/appstream/os',
      'content/eus/rhel8/8.2/x86_64/appstream/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/baseos/debug',
      'content/eus/rhel8/8.2/x86_64/baseos/os',
      'content/eus/rhel8/8.2/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/codeready-builder/debug',
      'content/eus/rhel8/8.2/x86_64/codeready-builder/os',
      'content/eus/rhel8/8.2/x86_64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/highavailability/debug',
      'content/eus/rhel8/8.2/x86_64/highavailability/os',
      'content/eus/rhel8/8.2/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/resilientstorage/debug',
      'content/eus/rhel8/8.2/x86_64/resilientstorage/os',
      'content/eus/rhel8/8.2/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/sap-solutions/debug',
      'content/eus/rhel8/8.2/x86_64/sap-solutions/os',
      'content/eus/rhel8/8.2/x86_64/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/sap/debug',
      'content/eus/rhel8/8.2/x86_64/sap/os',
      'content/eus/rhel8/8.2/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/supplementary/debug',
      'content/eus/rhel8/8.2/x86_64/supplementary/os',
      'content/eus/rhel8/8.2/x86_64/supplementary/source/SRPMS',
      'content/tus/rhel8/8.2/x86_64/appstream/debug',
      'content/tus/rhel8/8.2/x86_64/appstream/os',
      'content/tus/rhel8/8.2/x86_64/appstream/source/SRPMS',
      'content/tus/rhel8/8.2/x86_64/baseos/debug',
      'content/tus/rhel8/8.2/x86_64/baseos/os',
      'content/tus/rhel8/8.2/x86_64/baseos/source/SRPMS',
      'content/tus/rhel8/8.2/x86_64/highavailability/debug',
      'content/tus/rhel8/8.2/x86_64/highavailability/os',
      'content/tus/rhel8/8.2/x86_64/highavailability/source/SRPMS',
      'content/tus/rhel8/8.2/x86_64/nfv/debug',
      'content/tus/rhel8/8.2/x86_64/nfv/os',
      'content/tus/rhel8/8.2/x86_64/nfv/source/SRPMS',
      'content/tus/rhel8/8.2/x86_64/rt/debug',
      'content/tus/rhel8/8.2/x86_64/rt/os',
      'content/tus/rhel8/8.2/x86_64/rt/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'python-qt5-rpm-macros-5.13.1-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-pyqt5-sip-4.19.19-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-qt5-5.13.1-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-qt5-base-5.13.1-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-qt5-devel-5.13.1-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-sip-devel-4.19.19-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qgnomeplatform-0.4-3.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qgnomeplatform-0.4-3.el8', 'sp':'2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qgnomeplatform-0.4-3.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qgnomeplatform-0.4-3.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-assistant-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-designer-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-devel-5.12.5-3.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-doctools-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-linguist-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qdbusviewer-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qt3d-5.12.5-2.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qt3d-devel-5.12.5-2.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qt3d-examples-5.12.5-2.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-5.12.5-4.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-common-5.12.5-4.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-devel-5.12.5-4.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-examples-5.12.5-4.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-gui-5.12.5-4.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-mysql-5.12.5-4.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-odbc-5.12.5-4.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-postgresql-5.12.5-4.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-private-devel-5.12.5-4.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-static-5.12.5-4.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtcanvas3d-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtcanvas3d-examples-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtconnectivity-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtconnectivity-devel-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtconnectivity-examples-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtdeclarative-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtdeclarative-devel-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtdeclarative-examples-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtdeclarative-static-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtdoc-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtgraphicaleffects-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtimageformats-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtlocation-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtlocation-devel-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtlocation-examples-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtmultimedia-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtmultimedia-devel-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtmultimedia-examples-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtquickcontrols-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtquickcontrols-examples-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtquickcontrols2-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtquickcontrols2-devel-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtquickcontrols2-examples-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtscript-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtscript-devel-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtscript-examples-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtsensors-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtsensors-devel-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtsensors-examples-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtserialbus-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtserialbus-examples-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtserialport-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtserialport-devel-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtserialport-examples-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtsvg-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtsvg-devel-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtsvg-examples-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttools-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttools-common-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttools-devel-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttools-examples-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttools-libs-designer-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttools-libs-designercomponents-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttools-libs-help-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttools-static-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttranslations-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwayland-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwayland-devel-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwayland-examples-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwebchannel-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwebchannel-devel-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwebchannel-examples-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwebsockets-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwebsockets-devel-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwebsockets-examples-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtx11extras-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtx11extras-devel-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtxmlpatterns-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtxmlpatterns-devel-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtxmlpatterns-examples-5.12.5-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-rpm-macros-5.12.5-3.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-srpm-macros-5.12.5-3.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'sip-4.19.19-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/aus/rhel8/8.4/x86_64/appstream/debug',
      'content/aus/rhel8/8.4/x86_64/appstream/os',
      'content/aus/rhel8/8.4/x86_64/appstream/source/SRPMS',
      'content/aus/rhel8/8.4/x86_64/baseos/debug',
      'content/aus/rhel8/8.4/x86_64/baseos/os',
      'content/aus/rhel8/8.4/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.4/ppc64le/appstream/debug',
      'content/e4s/rhel8/8.4/ppc64le/appstream/os',
      'content/e4s/rhel8/8.4/ppc64le/appstream/source/SRPMS',
      'content/e4s/rhel8/8.4/ppc64le/baseos/debug',
      'content/e4s/rhel8/8.4/ppc64le/baseos/os',
      'content/e4s/rhel8/8.4/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel8/8.4/ppc64le/highavailability/debug',
      'content/e4s/rhel8/8.4/ppc64le/highavailability/os',
      'content/e4s/rhel8/8.4/ppc64le/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.4/ppc64le/sap-solutions/debug',
      'content/e4s/rhel8/8.4/ppc64le/sap-solutions/os',
      'content/e4s/rhel8/8.4/ppc64le/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.4/ppc64le/sap/debug',
      'content/e4s/rhel8/8.4/ppc64le/sap/os',
      'content/e4s/rhel8/8.4/ppc64le/sap/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/appstream/debug',
      'content/e4s/rhel8/8.4/x86_64/appstream/os',
      'content/e4s/rhel8/8.4/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/baseos/debug',
      'content/e4s/rhel8/8.4/x86_64/baseos/os',
      'content/e4s/rhel8/8.4/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/highavailability/debug',
      'content/e4s/rhel8/8.4/x86_64/highavailability/os',
      'content/e4s/rhel8/8.4/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/sap-solutions/debug',
      'content/e4s/rhel8/8.4/x86_64/sap-solutions/os',
      'content/e4s/rhel8/8.4/x86_64/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/sap/debug',
      'content/e4s/rhel8/8.4/x86_64/sap/os',
      'content/e4s/rhel8/8.4/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.4/aarch64/appstream/debug',
      'content/eus/rhel8/8.4/aarch64/appstream/os',
      'content/eus/rhel8/8.4/aarch64/appstream/source/SRPMS',
      'content/eus/rhel8/8.4/aarch64/baseos/debug',
      'content/eus/rhel8/8.4/aarch64/baseos/os',
      'content/eus/rhel8/8.4/aarch64/baseos/source/SRPMS',
      'content/eus/rhel8/8.4/aarch64/codeready-builder/debug',
      'content/eus/rhel8/8.4/aarch64/codeready-builder/os',
      'content/eus/rhel8/8.4/aarch64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.4/aarch64/highavailability/debug',
      'content/eus/rhel8/8.4/aarch64/highavailability/os',
      'content/eus/rhel8/8.4/aarch64/highavailability/source/SRPMS',
      'content/eus/rhel8/8.4/aarch64/supplementary/debug',
      'content/eus/rhel8/8.4/aarch64/supplementary/os',
      'content/eus/rhel8/8.4/aarch64/supplementary/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/appstream/debug',
      'content/eus/rhel8/8.4/ppc64le/appstream/os',
      'content/eus/rhel8/8.4/ppc64le/appstream/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/baseos/debug',
      'content/eus/rhel8/8.4/ppc64le/baseos/os',
      'content/eus/rhel8/8.4/ppc64le/baseos/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/codeready-builder/debug',
      'content/eus/rhel8/8.4/ppc64le/codeready-builder/os',
      'content/eus/rhel8/8.4/ppc64le/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/highavailability/debug',
      'content/eus/rhel8/8.4/ppc64le/highavailability/os',
      'content/eus/rhel8/8.4/ppc64le/highavailability/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/resilientstorage/debug',
      'content/eus/rhel8/8.4/ppc64le/resilientstorage/os',
      'content/eus/rhel8/8.4/ppc64le/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/sap-solutions/debug',
      'content/eus/rhel8/8.4/ppc64le/sap-solutions/os',
      'content/eus/rhel8/8.4/ppc64le/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/sap/debug',
      'content/eus/rhel8/8.4/ppc64le/sap/os',
      'content/eus/rhel8/8.4/ppc64le/sap/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/supplementary/debug',
      'content/eus/rhel8/8.4/ppc64le/supplementary/os',
      'content/eus/rhel8/8.4/ppc64le/supplementary/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/appstream/debug',
      'content/eus/rhel8/8.4/x86_64/appstream/os',
      'content/eus/rhel8/8.4/x86_64/appstream/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/baseos/debug',
      'content/eus/rhel8/8.4/x86_64/baseos/os',
      'content/eus/rhel8/8.4/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/codeready-builder/debug',
      'content/eus/rhel8/8.4/x86_64/codeready-builder/os',
      'content/eus/rhel8/8.4/x86_64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/highavailability/debug',
      'content/eus/rhel8/8.4/x86_64/highavailability/os',
      'content/eus/rhel8/8.4/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/resilientstorage/debug',
      'content/eus/rhel8/8.4/x86_64/resilientstorage/os',
      'content/eus/rhel8/8.4/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/sap-solutions/debug',
      'content/eus/rhel8/8.4/x86_64/sap-solutions/os',
      'content/eus/rhel8/8.4/x86_64/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/sap/debug',
      'content/eus/rhel8/8.4/x86_64/sap/os',
      'content/eus/rhel8/8.4/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/supplementary/debug',
      'content/eus/rhel8/8.4/x86_64/supplementary/os',
      'content/eus/rhel8/8.4/x86_64/supplementary/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/appstream/debug',
      'content/tus/rhel8/8.4/x86_64/appstream/os',
      'content/tus/rhel8/8.4/x86_64/appstream/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/baseos/debug',
      'content/tus/rhel8/8.4/x86_64/baseos/os',
      'content/tus/rhel8/8.4/x86_64/baseos/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/highavailability/debug',
      'content/tus/rhel8/8.4/x86_64/highavailability/os',
      'content/tus/rhel8/8.4/x86_64/highavailability/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/nfv/debug',
      'content/tus/rhel8/8.4/x86_64/nfv/os',
      'content/tus/rhel8/8.4/x86_64/nfv/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/rt/debug',
      'content/tus/rhel8/8.4/x86_64/rt/os',
      'content/tus/rhel8/8.4/x86_64/rt/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'python-qt5-rpm-macros-5.13.1-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-pyqt5-sip-4.19.19-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-qt5-5.13.1-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-qt5-base-5.13.1-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-qt5-devel-5.13.1-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-sip-devel-4.19.19-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qgnomeplatform-0.4-3.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qgnomeplatform-0.4-3.el8', 'sp':'4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qgnomeplatform-0.4-3.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qgnomeplatform-0.4-3.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-assistant-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-designer-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-devel-5.12.5-3.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-doctools-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-linguist-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qdbusviewer-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qt3d-5.12.5-2.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qt3d-devel-5.12.5-2.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qt3d-examples-5.12.5-2.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-5.12.5-4.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-common-5.12.5-4.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-devel-5.12.5-4.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-examples-5.12.5-4.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-gui-5.12.5-4.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-mysql-5.12.5-4.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-odbc-5.12.5-4.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-postgresql-5.12.5-4.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-private-devel-5.12.5-4.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-static-5.12.5-4.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtcanvas3d-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtcanvas3d-examples-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtconnectivity-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtconnectivity-devel-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtconnectivity-examples-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtdeclarative-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtdeclarative-devel-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtdeclarative-examples-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtdeclarative-static-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtdoc-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtgraphicaleffects-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtimageformats-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtlocation-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtlocation-devel-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtlocation-examples-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtmultimedia-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtmultimedia-devel-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtmultimedia-examples-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtquickcontrols-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtquickcontrols-examples-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtquickcontrols2-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtquickcontrols2-devel-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtquickcontrols2-examples-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtscript-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtscript-devel-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtscript-examples-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtsensors-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtsensors-devel-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtsensors-examples-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtserialbus-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtserialbus-examples-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtserialport-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtserialport-devel-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtserialport-examples-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtsvg-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtsvg-devel-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtsvg-examples-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttools-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttools-common-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttools-devel-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttools-examples-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttools-libs-designer-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttools-libs-designercomponents-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttools-libs-help-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttools-static-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttranslations-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwayland-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwayland-devel-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwayland-examples-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwebchannel-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwebchannel-devel-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwebchannel-examples-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwebsockets-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwebsockets-devel-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwebsockets-examples-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtx11extras-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtx11extras-devel-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtxmlpatterns-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtxmlpatterns-devel-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtxmlpatterns-examples-5.12.5-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-rpm-macros-5.12.5-3.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-srpm-macros-5.12.5-3.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'sip-4.19.19-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/aus/rhel8/8.6/x86_64/appstream/debug',
      'content/aus/rhel8/8.6/x86_64/appstream/os',
      'content/aus/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/aus/rhel8/8.6/x86_64/baseos/debug',
      'content/aus/rhel8/8.6/x86_64/baseos/os',
      'content/aus/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.6/ppc64le/appstream/debug',
      'content/e4s/rhel8/8.6/ppc64le/appstream/os',
      'content/e4s/rhel8/8.6/ppc64le/appstream/source/SRPMS',
      'content/e4s/rhel8/8.6/ppc64le/baseos/debug',
      'content/e4s/rhel8/8.6/ppc64le/baseos/os',
      'content/e4s/rhel8/8.6/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel8/8.6/ppc64le/highavailability/debug',
      'content/e4s/rhel8/8.6/ppc64le/highavailability/os',
      'content/e4s/rhel8/8.6/ppc64le/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.6/ppc64le/sap-solutions/debug',
      'content/e4s/rhel8/8.6/ppc64le/sap-solutions/os',
      'content/e4s/rhel8/8.6/ppc64le/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.6/ppc64le/sap/debug',
      'content/e4s/rhel8/8.6/ppc64le/sap/os',
      'content/e4s/rhel8/8.6/ppc64le/sap/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/appstream/debug',
      'content/e4s/rhel8/8.6/x86_64/appstream/os',
      'content/e4s/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/baseos/debug',
      'content/e4s/rhel8/8.6/x86_64/baseos/os',
      'content/e4s/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/highavailability/debug',
      'content/e4s/rhel8/8.6/x86_64/highavailability/os',
      'content/e4s/rhel8/8.6/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/sap-solutions/debug',
      'content/e4s/rhel8/8.6/x86_64/sap-solutions/os',
      'content/e4s/rhel8/8.6/x86_64/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/sap/debug',
      'content/e4s/rhel8/8.6/x86_64/sap/os',
      'content/e4s/rhel8/8.6/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.6/aarch64/appstream/debug',
      'content/eus/rhel8/8.6/aarch64/appstream/os',
      'content/eus/rhel8/8.6/aarch64/appstream/source/SRPMS',
      'content/eus/rhel8/8.6/aarch64/baseos/debug',
      'content/eus/rhel8/8.6/aarch64/baseos/os',
      'content/eus/rhel8/8.6/aarch64/baseos/source/SRPMS',
      'content/eus/rhel8/8.6/aarch64/codeready-builder/debug',
      'content/eus/rhel8/8.6/aarch64/codeready-builder/os',
      'content/eus/rhel8/8.6/aarch64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.6/aarch64/highavailability/debug',
      'content/eus/rhel8/8.6/aarch64/highavailability/os',
      'content/eus/rhel8/8.6/aarch64/highavailability/source/SRPMS',
      'content/eus/rhel8/8.6/aarch64/supplementary/debug',
      'content/eus/rhel8/8.6/aarch64/supplementary/os',
      'content/eus/rhel8/8.6/aarch64/supplementary/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/appstream/debug',
      'content/eus/rhel8/8.6/ppc64le/appstream/os',
      'content/eus/rhel8/8.6/ppc64le/appstream/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/baseos/debug',
      'content/eus/rhel8/8.6/ppc64le/baseos/os',
      'content/eus/rhel8/8.6/ppc64le/baseos/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/codeready-builder/debug',
      'content/eus/rhel8/8.6/ppc64le/codeready-builder/os',
      'content/eus/rhel8/8.6/ppc64le/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/highavailability/debug',
      'content/eus/rhel8/8.6/ppc64le/highavailability/os',
      'content/eus/rhel8/8.6/ppc64le/highavailability/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/resilientstorage/debug',
      'content/eus/rhel8/8.6/ppc64le/resilientstorage/os',
      'content/eus/rhel8/8.6/ppc64le/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/sap-solutions/debug',
      'content/eus/rhel8/8.6/ppc64le/sap-solutions/os',
      'content/eus/rhel8/8.6/ppc64le/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/sap/debug',
      'content/eus/rhel8/8.6/ppc64le/sap/os',
      'content/eus/rhel8/8.6/ppc64le/sap/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/supplementary/debug',
      'content/eus/rhel8/8.6/ppc64le/supplementary/os',
      'content/eus/rhel8/8.6/ppc64le/supplementary/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/appstream/debug',
      'content/eus/rhel8/8.6/x86_64/appstream/os',
      'content/eus/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/baseos/debug',
      'content/eus/rhel8/8.6/x86_64/baseos/os',
      'content/eus/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/codeready-builder/debug',
      'content/eus/rhel8/8.6/x86_64/codeready-builder/os',
      'content/eus/rhel8/8.6/x86_64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/highavailability/debug',
      'content/eus/rhel8/8.6/x86_64/highavailability/os',
      'content/eus/rhel8/8.6/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/resilientstorage/debug',
      'content/eus/rhel8/8.6/x86_64/resilientstorage/os',
      'content/eus/rhel8/8.6/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/sap-solutions/debug',
      'content/eus/rhel8/8.6/x86_64/sap-solutions/os',
      'content/eus/rhel8/8.6/x86_64/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/sap/debug',
      'content/eus/rhel8/8.6/x86_64/sap/os',
      'content/eus/rhel8/8.6/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/supplementary/debug',
      'content/eus/rhel8/8.6/x86_64/supplementary/os',
      'content/eus/rhel8/8.6/x86_64/supplementary/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/appstream/debug',
      'content/tus/rhel8/8.6/x86_64/appstream/os',
      'content/tus/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/baseos/debug',
      'content/tus/rhel8/8.6/x86_64/baseos/os',
      'content/tus/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/highavailability/debug',
      'content/tus/rhel8/8.6/x86_64/highavailability/os',
      'content/tus/rhel8/8.6/x86_64/highavailability/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/rt/os',
      'content/tus/rhel8/8.6/x86_64/rt/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'python-qt5-rpm-macros-5.13.1-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-pyqt5-sip-4.19.19-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-qt5-5.13.1-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-qt5-base-5.13.1-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-qt5-devel-5.13.1-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-sip-devel-4.19.19-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qgnomeplatform-0.4-3.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qgnomeplatform-0.4-3.el8', 'sp':'6', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qgnomeplatform-0.4-3.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qgnomeplatform-0.4-3.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-assistant-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-designer-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-devel-5.12.5-3.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-doctools-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-linguist-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qdbusviewer-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qt3d-5.12.5-2.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qt3d-devel-5.12.5-2.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qt3d-examples-5.12.5-2.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-5.12.5-4.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-common-5.12.5-4.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-devel-5.12.5-4.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-examples-5.12.5-4.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-gui-5.12.5-4.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-mysql-5.12.5-4.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-odbc-5.12.5-4.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-postgresql-5.12.5-4.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-private-devel-5.12.5-4.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-static-5.12.5-4.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtcanvas3d-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtcanvas3d-examples-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtconnectivity-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtconnectivity-devel-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtconnectivity-examples-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtdeclarative-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtdeclarative-devel-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtdeclarative-examples-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtdeclarative-static-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtdoc-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtgraphicaleffects-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtimageformats-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtlocation-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtlocation-devel-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtlocation-examples-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtmultimedia-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtmultimedia-devel-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtmultimedia-examples-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtquickcontrols-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtquickcontrols-examples-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtquickcontrols2-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtquickcontrols2-devel-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtquickcontrols2-examples-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtscript-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtscript-devel-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtscript-examples-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtsensors-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtsensors-devel-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtsensors-examples-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtserialbus-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtserialbus-examples-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtserialport-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtserialport-devel-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtserialport-examples-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtsvg-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtsvg-devel-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtsvg-examples-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttools-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttools-common-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttools-devel-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttools-examples-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttools-libs-designer-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttools-libs-designercomponents-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttools-libs-help-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttools-static-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttranslations-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwayland-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwayland-devel-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwayland-examples-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwebchannel-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwebchannel-devel-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwebchannel-examples-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwebsockets-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwebsockets-devel-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwebsockets-examples-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtx11extras-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtx11extras-devel-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtxmlpatterns-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtxmlpatterns-devel-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtxmlpatterns-examples-5.12.5-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-rpm-macros-5.12.5-3.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-srpm-macros-5.12.5-3.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'sip-4.19.19-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel8/8/aarch64/appstream/debug',
      'content/dist/rhel8/8/aarch64/appstream/os',
      'content/dist/rhel8/8/aarch64/appstream/source/SRPMS',
      'content/dist/rhel8/8/aarch64/baseos/debug',
      'content/dist/rhel8/8/aarch64/baseos/os',
      'content/dist/rhel8/8/aarch64/baseos/source/SRPMS',
      'content/dist/rhel8/8/aarch64/codeready-builder/debug',
      'content/dist/rhel8/8/aarch64/codeready-builder/os',
      'content/dist/rhel8/8/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/aarch64/highavailability/debug',
      'content/dist/rhel8/8/aarch64/highavailability/os',
      'content/dist/rhel8/8/aarch64/highavailability/source/SRPMS',
      'content/dist/rhel8/8/aarch64/supplementary/debug',
      'content/dist/rhel8/8/aarch64/supplementary/os',
      'content/dist/rhel8/8/aarch64/supplementary/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/appstream/debug',
      'content/dist/rhel8/8/ppc64le/appstream/os',
      'content/dist/rhel8/8/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/baseos/debug',
      'content/dist/rhel8/8/ppc64le/baseos/os',
      'content/dist/rhel8/8/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/codeready-builder/debug',
      'content/dist/rhel8/8/ppc64le/codeready-builder/os',
      'content/dist/rhel8/8/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/highavailability/debug',
      'content/dist/rhel8/8/ppc64le/highavailability/os',
      'content/dist/rhel8/8/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/resilientstorage/debug',
      'content/dist/rhel8/8/ppc64le/resilientstorage/os',
      'content/dist/rhel8/8/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/sap-solutions/debug',
      'content/dist/rhel8/8/ppc64le/sap-solutions/os',
      'content/dist/rhel8/8/ppc64le/sap-solutions/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/sap/debug',
      'content/dist/rhel8/8/ppc64le/sap/os',
      'content/dist/rhel8/8/ppc64le/sap/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/supplementary/debug',
      'content/dist/rhel8/8/ppc64le/supplementary/os',
      'content/dist/rhel8/8/ppc64le/supplementary/source/SRPMS',
      'content/dist/rhel8/8/x86_64/appstream/debug',
      'content/dist/rhel8/8/x86_64/appstream/os',
      'content/dist/rhel8/8/x86_64/appstream/source/SRPMS',
      'content/dist/rhel8/8/x86_64/baseos/debug',
      'content/dist/rhel8/8/x86_64/baseos/os',
      'content/dist/rhel8/8/x86_64/baseos/source/SRPMS',
      'content/dist/rhel8/8/x86_64/codeready-builder/debug',
      'content/dist/rhel8/8/x86_64/codeready-builder/os',
      'content/dist/rhel8/8/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/x86_64/highavailability/debug',
      'content/dist/rhel8/8/x86_64/highavailability/os',
      'content/dist/rhel8/8/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel8/8/x86_64/nfv/debug',
      'content/dist/rhel8/8/x86_64/nfv/os',
      'content/dist/rhel8/8/x86_64/nfv/source/SRPMS',
      'content/dist/rhel8/8/x86_64/resilientstorage/debug',
      'content/dist/rhel8/8/x86_64/resilientstorage/os',
      'content/dist/rhel8/8/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel8/8/x86_64/rt/debug',
      'content/dist/rhel8/8/x86_64/rt/os',
      'content/dist/rhel8/8/x86_64/rt/source/SRPMS',
      'content/dist/rhel8/8/x86_64/sap-solutions/debug',
      'content/dist/rhel8/8/x86_64/sap-solutions/os',
      'content/dist/rhel8/8/x86_64/sap-solutions/source/SRPMS',
      'content/dist/rhel8/8/x86_64/sap/debug',
      'content/dist/rhel8/8/x86_64/sap/os',
      'content/dist/rhel8/8/x86_64/sap/source/SRPMS',
      'content/dist/rhel8/8/x86_64/supplementary/debug',
      'content/dist/rhel8/8/x86_64/supplementary/os',
      'content/dist/rhel8/8/x86_64/supplementary/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'python-qt5-rpm-macros-5.13.1-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-pyqt5-sip-4.19.19-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-qt5-5.13.1-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-qt5-base-5.13.1-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-qt5-devel-5.13.1-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-sip-devel-4.19.19-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qgnomeplatform-0.4-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qgnomeplatform-0.4-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qgnomeplatform-0.4-3.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qgnomeplatform-0.4-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-assistant-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-designer-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-devel-5.12.5-3.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-doctools-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-linguist-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qdbusviewer-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qt3d-5.12.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qt3d-devel-5.12.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qt3d-examples-5.12.5-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-5.12.5-4.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-common-5.12.5-4.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-devel-5.12.5-4.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-examples-5.12.5-4.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-gui-5.12.5-4.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-mysql-5.12.5-4.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-odbc-5.12.5-4.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-postgresql-5.12.5-4.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-private-devel-5.12.5-4.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtbase-static-5.12.5-4.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtcanvas3d-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtcanvas3d-examples-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtconnectivity-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtconnectivity-devel-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtconnectivity-examples-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtdeclarative-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtdeclarative-devel-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtdeclarative-examples-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtdeclarative-static-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtdoc-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtgraphicaleffects-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtimageformats-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtlocation-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtlocation-devel-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtlocation-examples-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtmultimedia-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtmultimedia-devel-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtmultimedia-examples-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtquickcontrols-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtquickcontrols-examples-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtquickcontrols2-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtquickcontrols2-devel-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtquickcontrols2-examples-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtscript-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtscript-devel-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtscript-examples-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtsensors-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtsensors-devel-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtsensors-examples-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtserialbus-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtserialbus-examples-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtserialport-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtserialport-devel-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtserialport-examples-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtsvg-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtsvg-devel-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtsvg-examples-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttools-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttools-common-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttools-devel-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttools-examples-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttools-libs-designer-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttools-libs-designercomponents-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttools-libs-help-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttools-static-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qttranslations-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwayland-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwayland-devel-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwayland-examples-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwebchannel-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwebchannel-devel-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwebchannel-examples-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwebsockets-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwebsockets-devel-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtwebsockets-examples-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtx11extras-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtx11extras-devel-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtxmlpatterns-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtxmlpatterns-devel-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-qtxmlpatterns-examples-5.12.5-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-rpm-macros-5.12.5-3.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qt5-srpm-macros-5.12.5-3.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'sip-4.19.19-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  var enterprise_linux_flag = rhel_repo_urls_has_content_dist_rhel(repo_urls:repo_relative_urls);
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp']) && !enterprise_linux_flag) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get() + redhat_report_package_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-qt5-rpm-macros / python3-pyqt5-sip / python3-qt5 / etc');
}
