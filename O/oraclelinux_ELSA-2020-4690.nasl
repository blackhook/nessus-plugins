##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-4690.
##

include('compat.inc');

if (description)
{
  script_id(142803);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/13");

  script_cve_id(
    "CVE-2015-9541",
    "CVE-2018-21035",
    "CVE-2020-0569",
    "CVE-2020-0570",
    "CVE-2020-13962"
  );

  script_name(english:"Oracle Linux 8 : qt5-qtbase / and / qt5-qtwebsockets (ELSA-2020-4690)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2020-4690 advisory.

  - Qt through 5.14 allows an exponential XML entity expansion attack via a crafted SVG document that is
    mishandled in QXmlStreamReader, a related issue to CVE-2003-1564. (CVE-2015-9541)

  - In Qt through 5.14.1, the WebSocket implementation accepts up to 2GB for frames and 2GB for messages.
    Smaller limits cannot be configured. This makes it easier for attackers to cause a denial of service
    (memory consumption). (CVE-2018-21035)

  - Qt 5.12.2 through 5.14.2, as used in unofficial builds of Mumble 1.3.0 and other products, mishandles
    OpenSSL's error queue, which can cause a denial of service to QSslSocket users. Because errors leak in
    unrelated TLS sessions, an unrelated session may be disconnected when any handshake fails. (Mumble 1.3.1
    is not affected, regardless of the Qt version.) (CVE-2020-13962)

  - qt: files placed by attacker can influence the working directory and lead to malicious code execution
    (CVE-2020-0569)

  - Uncontrolled search path in the QT Library before 5.14.0, 5.12.7 and 5.9.10 may allow an authenticated
    user to potentially enable elevation of privilege via local access. (CVE-2020-0570)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2020-4690.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0570");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-assistant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-designer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-doctools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-linguist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qdbusviewer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtbase-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtbase-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtbase-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtbase-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtbase-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtbase-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtbase-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtbase-private-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtbase-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qttools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qttools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qttools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qttools-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qttools-libs-designer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qttools-libs-designercomponents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qttools-libs-help");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qttools-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtwebsockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtwebsockets-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtwebsockets-examples");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

pkgs = [
    {'reference':'qt5-assistant-5.12.5-2.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'qt5-assistant-5.12.5-2.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'qt5-designer-5.12.5-2.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'qt5-designer-5.12.5-2.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'qt5-doctools-5.12.5-2.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'qt5-doctools-5.12.5-2.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'qt5-linguist-5.12.5-2.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'qt5-linguist-5.12.5-2.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'qt5-qdbusviewer-5.12.5-2.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'qt5-qdbusviewer-5.12.5-2.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'qt5-qtbase-5.12.5-6.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'qt5-qtbase-5.12.5-6.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'qt5-qtbase-5.12.5-6.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'qt5-qtbase-common-5.12.5-6.el8', 'release':'8'},
    {'reference':'qt5-qtbase-devel-5.12.5-6.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'qt5-qtbase-devel-5.12.5-6.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'qt5-qtbase-devel-5.12.5-6.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'qt5-qtbase-examples-5.12.5-6.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'qt5-qtbase-examples-5.12.5-6.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'qt5-qtbase-examples-5.12.5-6.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'qt5-qtbase-gui-5.12.5-6.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'qt5-qtbase-gui-5.12.5-6.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'qt5-qtbase-gui-5.12.5-6.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'qt5-qtbase-mysql-5.12.5-6.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'qt5-qtbase-mysql-5.12.5-6.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'qt5-qtbase-mysql-5.12.5-6.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'qt5-qtbase-odbc-5.12.5-6.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'qt5-qtbase-odbc-5.12.5-6.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'qt5-qtbase-odbc-5.12.5-6.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'qt5-qtbase-postgresql-5.12.5-6.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'qt5-qtbase-postgresql-5.12.5-6.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'qt5-qtbase-postgresql-5.12.5-6.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'qt5-qtbase-private-devel-5.12.5-6.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'qt5-qtbase-private-devel-5.12.5-6.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'qt5-qtbase-private-devel-5.12.5-6.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'qt5-qtbase-static-5.12.5-6.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'qt5-qtbase-static-5.12.5-6.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'qt5-qtbase-static-5.12.5-6.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'qt5-qttools-5.12.5-2.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'qt5-qttools-5.12.5-2.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'qt5-qttools-common-5.12.5-2.el8', 'release':'8'},
    {'reference':'qt5-qttools-devel-5.12.5-2.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'qt5-qttools-devel-5.12.5-2.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'qt5-qttools-devel-5.12.5-2.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'qt5-qttools-examples-5.12.5-2.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'qt5-qttools-examples-5.12.5-2.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'qt5-qttools-examples-5.12.5-2.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'qt5-qttools-libs-designer-5.12.5-2.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'qt5-qttools-libs-designer-5.12.5-2.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'qt5-qttools-libs-designer-5.12.5-2.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'qt5-qttools-libs-designercomponents-5.12.5-2.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'qt5-qttools-libs-designercomponents-5.12.5-2.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'qt5-qttools-libs-designercomponents-5.12.5-2.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'qt5-qttools-libs-help-5.12.5-2.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'qt5-qttools-libs-help-5.12.5-2.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'qt5-qttools-libs-help-5.12.5-2.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'qt5-qttools-static-5.12.5-2.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'qt5-qttools-static-5.12.5-2.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'qt5-qttools-static-5.12.5-2.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'qt5-qtwebsockets-5.12.5-2.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'qt5-qtwebsockets-5.12.5-2.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'qt5-qtwebsockets-5.12.5-2.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'qt5-qtwebsockets-devel-5.12.5-2.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'qt5-qtwebsockets-devel-5.12.5-2.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'qt5-qtwebsockets-devel-5.12.5-2.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'qt5-qtwebsockets-examples-5.12.5-2.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'qt5-qtwebsockets-examples-5.12.5-2.el8', 'cpu':'x86_64', 'release':'8'}
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
  rpm_prefix = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['rpm_prefix'])) rpm_prefix = package_array['rpm_prefix'];
  if (reference && release) {
    if (rpm_prefix) {
        if (rpm_exists(release:release, rpm:rpm_prefix) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qt5-assistant / qt5-designer / qt5-doctools / etc');
}