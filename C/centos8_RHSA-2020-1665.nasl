##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2020:1665. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145955);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id("CVE-2018-19869", "CVE-2018-19871", "CVE-2018-19872");
  script_bugtraq_id(106338);
  script_xref(name:"RHSA", value:"2020:1665");

  script_name(english:"CentOS 8 : qt5 (CESA-2020:1665)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2020:1665 advisory.

  - qt5-qtsvg: Invalid parsing of malformed url reference resulting in a denial of service (CVE-2018-19869)

  - qt5-qtimageformats: QTgaFile CPU exhaustion (CVE-2018-19871)

  - qt: Malformed PPM image causing division by zero and crash in qppmhandler.cpp (CVE-2018-19872)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:1665");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19872");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-19871");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-qt5-rpm-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-pyqt5-sip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-qt5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-qt5-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-qt5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-sip-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qgnomeplatform");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qt3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qt3d-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qt3d-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtbase-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtbase-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtbase-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtbase-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtbase-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtbase-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtbase-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtbase-private-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtbase-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtcanvas3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtcanvas3d-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtconnectivity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtconnectivity-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtconnectivity-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtdeclarative");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtdeclarative-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtdeclarative-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtdeclarative-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtgraphicaleffects");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtimageformats");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtlocation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtlocation-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtlocation-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtmultimedia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtmultimedia-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtmultimedia-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtquickcontrols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtquickcontrols-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtquickcontrols2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtquickcontrols2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtquickcontrols2-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtscript-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtsensors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtsensors-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtsensors-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtserialbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtserialbus-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtserialport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtserialport-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtserialport-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtsvg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtsvg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtsvg-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qttranslations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtwayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtwayland-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtwayland-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtwebchannel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtwebchannel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtwebchannel-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtwebsockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtwebsockets-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtwebsockets-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtx11extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtx11extras-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtxmlpatterns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtxmlpatterns-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtxmlpatterns-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-rpm-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-srpm-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sip");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/CentOS/release');
if (isnull(release) || 'CentOS' >!< release) audit(AUDIT_OS_NOT, 'CentOS');
os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if ('CentOS Stream' >< release) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS Stream ' + os_ver);
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

pkgs = [
    {'reference':'python-qt5-rpm-macros-5.13.1-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-qt5-rpm-macros-5.13.1-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-pyqt5-sip-4.19.19-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-pyqt5-sip-4.19.19-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-qt5-5.13.1-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-qt5-5.13.1-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-qt5-base-5.13.1-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-qt5-base-5.13.1-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-qt5-devel-5.13.1-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-qt5-devel-5.13.1-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-sip-devel-4.19.19-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-sip-devel-4.19.19-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qgnomeplatform-0.4-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qgnomeplatform-0.4-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-devel-5.12.5-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-devel-5.12.5-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qt3d-5.12.5-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qt3d-5.12.5-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qt3d-devel-5.12.5-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qt3d-devel-5.12.5-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qt3d-examples-5.12.5-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qt3d-examples-5.12.5-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-5.12.5-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-5.12.5-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-common-5.12.5-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-common-5.12.5-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-devel-5.12.5-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-devel-5.12.5-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-examples-5.12.5-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-examples-5.12.5-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-gui-5.12.5-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-gui-5.12.5-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-mysql-5.12.5-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-mysql-5.12.5-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-odbc-5.12.5-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-odbc-5.12.5-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-postgresql-5.12.5-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-postgresql-5.12.5-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-private-devel-5.12.5-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-private-devel-5.12.5-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-static-5.12.5-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-static-5.12.5-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtcanvas3d-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtcanvas3d-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtcanvas3d-examples-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtcanvas3d-examples-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtconnectivity-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtconnectivity-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtconnectivity-devel-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtconnectivity-devel-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtconnectivity-examples-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtconnectivity-examples-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtdeclarative-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtdeclarative-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtdeclarative-devel-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtdeclarative-devel-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtdeclarative-examples-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtdeclarative-examples-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtdeclarative-static-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtdeclarative-static-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtdoc-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtdoc-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtgraphicaleffects-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtgraphicaleffects-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtimageformats-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtimageformats-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtlocation-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtlocation-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtlocation-devel-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtlocation-devel-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtlocation-examples-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtlocation-examples-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtmultimedia-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtmultimedia-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtmultimedia-devel-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtmultimedia-devel-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtmultimedia-examples-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtmultimedia-examples-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtquickcontrols-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtquickcontrols-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtquickcontrols-examples-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtquickcontrols-examples-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtquickcontrols2-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtquickcontrols2-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtquickcontrols2-devel-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtquickcontrols2-devel-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtquickcontrols2-examples-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtquickcontrols2-examples-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtscript-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtscript-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtscript-devel-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtscript-devel-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtscript-examples-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtscript-examples-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsensors-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsensors-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsensors-devel-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsensors-devel-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsensors-examples-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsensors-examples-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialbus-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialbus-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialbus-examples-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialbus-examples-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialport-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialport-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialport-devel-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialport-devel-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialport-examples-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialport-examples-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsvg-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsvg-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsvg-devel-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsvg-devel-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsvg-examples-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsvg-examples-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttranslations-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttranslations-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwayland-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwayland-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwayland-devel-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwayland-devel-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwayland-examples-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwayland-examples-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebchannel-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebchannel-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebchannel-devel-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebchannel-devel-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebchannel-examples-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebchannel-examples-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebsockets-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebsockets-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebsockets-devel-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebsockets-devel-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebsockets-examples-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebsockets-examples-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtx11extras-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtx11extras-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtx11extras-devel-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtx11extras-devel-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtxmlpatterns-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtxmlpatterns-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtxmlpatterns-devel-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtxmlpatterns-devel-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtxmlpatterns-examples-5.12.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtxmlpatterns-examples-5.12.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-rpm-macros-5.12.5-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-rpm-macros-5.12.5-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-srpm-macros-5.12.5-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-srpm-macros-5.12.5-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sip-4.19.19-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sip-4.19.19-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'CentOS-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-qt5-rpm-macros / python3-pyqt5-sip / python3-qt5 / etc');
}
