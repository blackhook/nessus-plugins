##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-0966.
##

include('compat.inc');

if (description)
{
  script_id(148035);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/11");

  script_cve_id("CVE-2021-20179");

  script_name(english:"Oracle Linux 8 : pki-core:10.6 (ELSA-2021-0966)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2021-0966 advisory.

  - A flaw was found in pki-core. An attacker who has successfully compromised a key could use this flaw to
    renew the corresponding certificate over and over again, as long as it is not explicitly revoked. The
    highest threat from this vulnerability is to data confidentiality and integrity. (CVE-2021-20179)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-0966.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20179");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:jss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:jss-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ldapjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ldapjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-base-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-kra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-symkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-pki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcatjss");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

module_ver = get_kb_item('Host/RedHat/appstream/pki-core');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module pki-core:10.6');
if ('10.6' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module pki-core:' + module_ver);

appstreams = {
    'pki-core:10.6': [
      {'reference':'jss-4.7.3-1.module+el8.3.0+7857+983338ee', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jss-4.7.3-1.module+el8.3.0+7857+983338ee', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jss-javadoc-4.7.3-1.module+el8.3.0+7857+983338ee', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jss-javadoc-4.7.3-1.module+el8.3.0+7857+983338ee', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ldapjdk-4.22.0-1.module+el8.3.0+7857+983338ee', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ldapjdk-javadoc-4.22.0-1.module+el8.3.0+7857+983338ee', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-base-10.9.4-3.0.1.module+el8.3.0+el8+9692+a35cea4e', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-base-java-10.9.4-3.0.1.module+el8.3.0+el8+9692+a35cea4e', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-ca-10.9.4-3.0.1.module+el8.3.0+el8+9692+a35cea4e', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-kra-10.9.4-3.0.1.module+el8.3.0+el8+9692+a35cea4e', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-server-10.9.4-3.0.1.module+el8.3.0+el8+9692+a35cea4e', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-symkey-10.9.4-3.0.1.module+el8.3.0+el8+9692+a35cea4e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-symkey-10.9.4-3.0.1.module+el8.3.0+el8+9692+a35cea4e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-tools-10.9.4-3.0.1.module+el8.3.0+el8+9692+a35cea4e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-tools-10.9.4-3.0.1.module+el8.3.0+el8+9692+a35cea4e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-pki-10.9.4-3.0.1.module+el8.3.0+el8+9692+a35cea4e', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tomcatjss-7.5.0-1.module+el8.3.0+7857+983338ee', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

flag = 0;
appstreams_found = 0;
foreach module (keys(appstreams)) {
  appstream = NULL;
  appstream_name = NULL;
  appstream_version = NULL;
  appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach package_array ( appstreams[module] ) {
      reference = NULL;
      release = NULL;
      sp = NULL;
      cpu = NULL;
      el_string = NULL;
      rpm_spec_vers_cmp = NULL;
      epoch = NULL;
      allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
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
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module pki-core:10.6');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jss / jss-javadoc / ldapjdk / etc');
}
