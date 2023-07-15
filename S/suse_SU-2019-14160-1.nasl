#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2019:14160-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150540);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-2762",
    "CVE-2019-2766",
    "CVE-2019-2769",
    "CVE-2019-2816",
    "CVE-2019-4473",
    "CVE-2019-7317",
    "CVE-2019-11771",
    "CVE-2019-11775"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2019:14160-1");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"SUSE SLES11 Security Update : java-1_7_1-ibm (SUSE-SU-2019:14160-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2019:14160-1 advisory.

  - AIX builds of Eclipse OpenJ9 before 0.15.0 contain unused RPATHs which may facilitate code injection and
    privilege elevation by local users. (CVE-2019-11771)

  - All builds of Eclipse OpenJ9 prior to 0.15 contain a bug where the loop versioner may fail to privatize a
    value that is pulled out of the loop by versioning - for example if there is a condition that is moved out
    of the loop that reads a field we may not privatize the value of that field in the modified copy of the
    loop allowing the test to see one value of the field and subsequently the loop to see a modified field
    value without retesting the condition moved out of the loop. This can lead to a variety of different
    issues but read out of array bounds is one major consequence of these problems. (CVE-2019-11775)

  - Vulnerability in the Java SE, Java SE Embedded component of Oracle Java SE (subcomponent: Utilities).
    Supported versions that are affected are Java SE: 7u221, 8u212, 11.0.3 and 12.0.1; Java SE Embedded:
    8u211. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded.
    Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web
    Start applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code
    that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the
    APIs. CVSS 3.0 Base Score 5.3 (Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L). (CVE-2019-2762, CVE-2019-2769)

  - Vulnerability in the Java SE, Java SE Embedded component of Oracle Java SE (subcomponent: Networking).
    Supported versions that are affected are Java SE: 7u221, 8u212, 11.0.3 and 12.0.1; Java SE Embedded:
    8u211. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks require human interaction from a
    person other than the attacker. Successful attacks of this vulnerability can result in unauthorized read
    access to a subset of Java SE, Java SE Embedded accessible data. Note: This vulnerability applies to Java
    deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets
    (in Java SE 8), that load and run untrusted code (e.g., code that comes from the internet) and rely on the
    Java sandbox for security. This vulnerability can also be exploited by using APIs in the specified
    Component, e.g., through a web service which supplies data to the APIs. CVSS 3.0 Base Score 3.1
    (Confidentiality impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N). (CVE-2019-2766)

  - Vulnerability in the Java SE, Java SE Embedded component of Oracle Java SE (subcomponent: Networking).
    Supported versions that are affected are Java SE: 7u221, 8u212, 11.0.3 and 12.0.1; Java SE Embedded:
    8u211. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in
    unauthorized update, insert or delete access to some of Java SE, Java SE Embedded accessible data as well
    as unauthorized read access to a subset of Java SE, Java SE Embedded accessible data. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code that
    comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the
    APIs. CVSS 3.0 Base Score 4.8 (Confidentiality and Integrity impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N). (CVE-2019-2816)

  - Multiple binaries in IBM SDK, Java Technology Edition 7, 7R, and 8 on the AIX platform use insecure
    absolute RPATHs, which may facilitate code injection and privilege elevation by local users. IBM X-Force
    ID: 163984. (CVE-2019-4473)

  - png_image_free in png.c in libpng 1.6.x before 1.6.37 has a use-after-free because png_image_free_function
    is called under png_safe_execute. (CVE-2019-7317)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1141780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1141782");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1141783");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1141785");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1141789");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1147021");
  # https://lists.suse.com/pipermail/sle-security-updates/2019-September/005877.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?048dad06");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11771");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11775");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-2762");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-2766");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-2769");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-2816");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-4473");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-7317");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2816");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-4473");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_1-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_1-ibm-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_1-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_1-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_1-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
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
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES11', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);

pkgs = [
    {'reference':'java-1_7_1-ibm-1.7.1_sr4.50-26.44', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'java-1_7_1-ibm-alsa-1.7.1_sr4.50-26.44', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'java-1_7_1-ibm-alsa-1.7.1_sr4.50-26.44', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'java-1_7_1-ibm-devel-1.7.1_sr4.50-26.44', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'java-1_7_1-ibm-jdbc-1.7.1_sr4.50-26.44', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'java-1_7_1-ibm-plugin-1.7.1_sr4.50-26.44', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'java-1_7_1-ibm-plugin-1.7.1_sr4.50-26.44', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'java-1_7_1-ibm-1.7.1_sr4.50-26.44', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'java-1_7_1-ibm-alsa-1.7.1_sr4.50-26.44', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'java-1_7_1-ibm-alsa-1.7.1_sr4.50-26.44', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'java-1_7_1-ibm-devel-1.7.1_sr4.50-26.44', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'java-1_7_1-ibm-jdbc-1.7.1_sr4.50-26.44', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'java-1_7_1-ibm-plugin-1.7.1_sr4.50-26.44', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'java-1_7_1-ibm-plugin-1.7.1_sr4.50-26.44', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  exists_check = NULL;
  rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release && exists_check) {
    if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
  else if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-1_7_1-ibm / java-1_7_1-ibm-alsa / java-1_7_1-ibm-devel / etc');
}
