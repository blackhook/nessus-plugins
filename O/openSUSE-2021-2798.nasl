#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:2798-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152726);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2021-2161",
    "CVE-2021-2341",
    "CVE-2021-2369",
    "CVE-2021-2388"
  );
  script_xref(name:"IAVA", value:"2021-A-0195");
  script_xref(name:"IAVA", value:"2021-A-0327-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"openSUSE 15 Security Update : java-1_8_0-openjdk (openSUSE-SU-2021:2798-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:2798-1 advisory.

  - Vulnerability in the Java SE, Java SE Embedded, Oracle GraalVM Enterprise Edition product of Oracle Java
    SE (component: Libraries). Supported versions that are affected are Java SE: 7u291, 8u281, 11.0.10, 16;
    Java SE Embedded: 8u281; Oracle GraalVM Enterprise Edition: 19.3.5, 20.3.1.2 and 21.0.0.2. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded, Oracle GraalVM Enterprise Edition. Successful attacks of this
    vulnerability can result in unauthorized creation, deletion or modification access to critical data or all
    Java SE, Java SE Embedded, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability
    applies to Java deployments that load and run untrusted code (e.g., code that comes from the internet) and
    rely on the Java sandbox for security. It can also be exploited by supplying untrusted data to APIs in the
    specified Component. CVSS 3.1 Base Score 5.9 (Integrity impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N). (CVE-2021-2161)

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
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185056");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188565");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188566");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/QMTWQGCU5SAOKIQIUH6IN4LEQOIC2PS6/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5955c4c7");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-2161");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-2341");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-2369");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-2388");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2388");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'java-1_8_0-openjdk-1.8.0.302-3.55.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1_8_0-openjdk-accessibility-1.8.0.302-3.55.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1_8_0-openjdk-demo-1.8.0.302-3.55.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1_8_0-openjdk-devel-1.8.0.302-3.55.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1_8_0-openjdk-headless-1.8.0.302-3.55.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1_8_0-openjdk-javadoc-1.8.0.302-3.55.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1_8_0-openjdk-src-1.8.0.302-3.55.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-1_8_0-openjdk / java-1_8_0-openjdk-accessibility / etc');
}
