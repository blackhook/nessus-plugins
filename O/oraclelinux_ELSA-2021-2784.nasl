#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-2784.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151928);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/22");

  script_cve_id("CVE-2021-2341", "CVE-2021-2369", "CVE-2021-2388");

  script_name(english:"Oracle Linux 7 : java-11-openjdk (ELSA-2021-2784)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2021-2784 advisory.

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    Networking). Supported versions that are affected are Java SE: 7u301, 8u291, 11.0.11, 16.0.1; Oracle
    GraalVM Enterprise Edition: 20.3.2 and 21.1.0. Difficult to exploit vulnerability allows unauthenticated
    attacker with network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise
    Edition. Successful attacks require human interaction from a person other than the attacker. Successful
    attacks of this vulnerability can result in unauthorized read access to a subset of Java SE, Oracle
    GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments,
    typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load
    and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for
    security. This vulnerability does not apply to Java deployments, typically in servers, that load and run
    only trusted code (e.g., code installed by an administrator). CVSS 3.1 Base Score 3.1 (Confidentiality
    impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N). (CVE-2021-2341)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    Library). Supported versions that are affected are Java SE: 7u301, 8u291, 11.0.11, 16.0.1; Oracle GraalVM
    Enterprise Edition: 20.3.2 and 21.1.0. Easily exploitable vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise Edition.
    Successful attacks require human interaction from a person other than the attacker. Successful attacks of
    this vulnerability can result in unauthorized update, insert or delete access to some of Java SE, Oracle
    GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments,
    typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load
    and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for
    security. This vulnerability does not apply to Java deployments, typically in servers, that load and run
    only trusted code (e.g., code installed by an administrator). CVSS 3.1 Base Score 4.3 (Integrity impacts).
    CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N). (CVE-2021-2369)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    Hotspot). Supported versions that are affected are Java SE: 8u291, 11.0.11, 16.0.1; Oracle GraalVM
    Enterprise Edition: 20.3.2 and 21.1.0. Difficult to exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise Edition.
    Successful attacks require human interaction from a person other than the attacker. Successful attacks of
    this vulnerability can result in takeover of Java SE, Oracle GraalVM Enterprise Edition. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the
    internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java
    deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). CVSS 3.1 Base Score 7.5 (Confidentiality, Integrity and Availability impacts). CVSS
    Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H). (CVE-2021-2388)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-2784.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2388");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-javadoc-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-jmods");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-static-libs");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

pkgs = [
    {'reference':'java-11-openjdk-11.0.12.0.7-0.0.1.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-11.0.12.0.7-0.0.1.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-demo-11.0.12.0.7-0.0.1.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-demo-11.0.12.0.7-0.0.1.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-devel-11.0.12.0.7-0.0.1.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-devel-11.0.12.0.7-0.0.1.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-headless-11.0.12.0.7-0.0.1.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-headless-11.0.12.0.7-0.0.1.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-javadoc-11.0.12.0.7-0.0.1.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-javadoc-11.0.12.0.7-0.0.1.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-javadoc-zip-11.0.12.0.7-0.0.1.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-javadoc-zip-11.0.12.0.7-0.0.1.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-jmods-11.0.12.0.7-0.0.1.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-jmods-11.0.12.0.7-0.0.1.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-src-11.0.12.0.7-0.0.1.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-src-11.0.12.0.7-0.0.1.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-static-libs-11.0.12.0.7-0.0.1.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-static-libs-11.0.12.0.7-0.0.1.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
  exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release) {
    if (exists_check) {
        if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-11-openjdk / java-11-openjdk-demo / java-11-openjdk-devel / etc');
}
