#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-10024.
##

include('compat.inc');

if (description)
{
  script_id(168407);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2022-43753");

  script_name(english:"Oracle Linux 7 : spacewalk-backend / spacewalk-java (ELSA-2022-10024)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2022-10024 advisory.

  - A Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability in
    spacewalk/Uyuni of SUSE Linux Enterprise Module for SUSE Manager Server 4.2, SUSE Linux Enterprise Module
    for SUSE Manager Server 4.3, SUSE Manager Server 4.2 allows remote attackers to read files available to
    the user running the process, typically tomcat. This issue affects: SUSE Linux Enterprise Module for SUSE
    Manager Server 4.2 hub-xmlrpc-api-0.7-150300.3.9.2, inter-server-sync-0.2.4-150300.8.25.2, locale-
    formula-0.3-150300.3.3.2, py27-compat-salt-3000.3-150300.7.7.26.2, python-
    urlgrabber-3.10.2.1py2_3-150300.3.3.2, spacecmd-4.2.20-150300.4.30.2, spacewalk-
    backend-4.2.25-150300.4.32.4, spacewalk-client-tools-4.2.21-150300.4.27.3, spacewalk-
    java-4.2.43-150300.3.48.2, spacewalk-utils-4.2.18-150300.3.21.2, spacewalk-web-4.2.30-150300.3.30.3,
    susemanager-4.2.38-150300.3.44.3, susemanager-doc-indexes-4.2-150300.12.36.3, susemanager-
    docs_en-4.2-150300.12.36.2, susemanager-schema-4.2.25-150300.3.30.3, susemanager-sls versions prior to
    4.2.28. SUSE Linux Enterprise Module for SUSE Manager Server 4.3 spacewalk-java versions prior to 4.3.39.
    SUSE Manager Server 4.2 release-notes-susemanager versions prior to 4.2.10. (CVE-2022-43753)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-10024.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-43753");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:spacewalk-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:spacewalk-backend-app");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:spacewalk-backend-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:spacewalk-backend-cdn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:spacewalk-backend-config-files");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:spacewalk-backend-config-files-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:spacewalk-backend-config-files-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:spacewalk-backend-iss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:spacewalk-backend-iss-export");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:spacewalk-backend-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:spacewalk-backend-package-push-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:spacewalk-backend-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:spacewalk-backend-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:spacewalk-backend-sql-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:spacewalk-backend-sql-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:spacewalk-backend-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:spacewalk-backend-xml-export-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:spacewalk-backend-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:spacewalk-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:spacewalk-java-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:spacewalk-java-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:spacewalk-java-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:spacewalk-java-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:spacewalk-java-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:spacewalk-taskomatic");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var pkgs = [
    {'reference':'spacewalk-backend-2.10.28-1.0.13.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'spacewalk-backend-app-2.10.28-1.0.13.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'spacewalk-backend-applet-2.10.28-1.0.13.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'spacewalk-backend-cdn-2.10.28-1.0.13.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'spacewalk-backend-config-files-2.10.28-1.0.13.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'spacewalk-backend-config-files-common-2.10.28-1.0.13.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'spacewalk-backend-config-files-tool-2.10.28-1.0.13.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'spacewalk-backend-iss-2.10.28-1.0.13.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'spacewalk-backend-iss-export-2.10.28-1.0.13.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'spacewalk-backend-libs-2.10.28-1.0.13.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'spacewalk-backend-package-push-server-2.10.28-1.0.13.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'spacewalk-backend-server-2.10.28-1.0.13.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'spacewalk-backend-sql-2.10.28-1.0.13.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'spacewalk-backend-sql-oracle-2.10.28-1.0.13.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'spacewalk-backend-sql-postgresql-2.10.28-1.0.13.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'spacewalk-backend-tools-2.10.28-1.0.13.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'spacewalk-backend-xml-export-libs-2.10.28-1.0.13.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'spacewalk-backend-xmlrpc-2.10.28-1.0.13.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'spacewalk-java-2.10.19-1.0.15.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'spacewalk-java-config-2.10.19-1.0.15.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'spacewalk-java-lib-2.10.19-1.0.15.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'spacewalk-java-oracle-2.10.19-1.0.15.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'spacewalk-java-postgresql-2.10.19-1.0.15.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'spacewalk-java-tests-2.10.19-1.0.15.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'spacewalk-taskomatic-2.10.19-1.0.15.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'spacewalk-backend / spacewalk-backend-app / spacewalk-backend-applet / etc');
}
