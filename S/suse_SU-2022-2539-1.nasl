##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:2539-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(163431);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id(
    "CVE-2021-35561",
    "CVE-2022-21299",
    "CVE-2022-21426",
    "CVE-2022-21434",
    "CVE-2022-21443",
    "CVE-2022-21449",
    "CVE-2022-21476",
    "CVE-2022-21496"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:2539-1");

  script_name(english:"SUSE SLES12 Security Update : java-1_7_1-ibm (SUSE-SU-2022:2539-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:2539-1 advisory.

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    Utility). Supported versions that are affected are Java SE: 7u311, 8u301, 11.0.12, 17; Oracle GraalVM
    Enterprise Edition: 20.3.3 and 21.2.0. Easily exploitable vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise Edition.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a partial denial of
    service (partial DOS) of Java SE, Oracle GraalVM Enterprise Edition. Note: This vulnerability applies to
    Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java
    applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability can also be exploited by using APIs in the specified Component,
    e.g., through a web service which supplies data to the APIs. (CVE-2021-35561)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: JAXP). Supported versions that are affected are Oracle Java SE: 7u321, 8u311, 11.0.13, 17.01;
    Oracle GraalVM Enterprise Edition: 20.3.4 and 21.3.0. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle
    GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM Enterprise Edition.
    Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web
    Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from
    the internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by using
    APIs in the specified Component, e.g., through a web service which supplies data to the APIs.
    (CVE-2022-21299)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: JAXP). Supported versions that are affected are Oracle Java SE: 7u331, 8u321, 11.0.14, 17.0.2,
    18; Oracle GraalVM Enterprise Edition: 20.3.5, 21.3.1 and 22.0.0.2. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE,
    Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized
    ability to cause a partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM Enterprise
    Edition. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java
    Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes
    from the internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by
    using APIs in the specified Component, e.g., through a web service which supplies data to the APIs.
    (CVE-2022-21426)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Libraries). Supported versions that are affected are Oracle Java SE: 7u331, 8u321, 11.0.14,
    17.0.2, 18; Oracle GraalVM Enterprise Edition: 20.3.5, 21.3.1 and 22.0.0.2. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise
    Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in
    unauthorized update, insert or delete access to some of Oracle Java SE, Oracle GraalVM Enterprise Edition
    accessible data. Note: This vulnerability applies to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g.,
    code that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also
    be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to
    the APIs. (CVE-2022-21434)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Libraries). Supported versions that are affected are Oracle Java SE: 7u331, 8u321, 11.0.14,
    17.0.2, 18; Oracle GraalVM Enterprise Edition: 20.3.5, 21.3.1 and 22.0.0.2. Difficult to exploit
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise
    Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM
    Enterprise Edition. Note: This vulnerability applies to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g.,
    code that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also
    be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to
    the APIs. (CVE-2022-21443)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Libraries). Supported versions that are affected are Oracle Java SE: 17.0.2 and 18; Oracle
    GraalVM Enterprise Edition: 21.3.1 and 22.0.0.2. Easily exploitable vulnerability allows unauthenticated
    attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM
    Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized creation, deletion
    or modification access to critical data or all Oracle Java SE, Oracle GraalVM Enterprise Edition
    accessible data. Note: This vulnerability applies to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g.,
    code that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also
    be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to
    the APIs. (CVE-2022-21449)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Libraries). Supported versions that are affected are Oracle Java SE: 7u331, 8u321, 11.0.14,
    17.0.2, 18; Oracle GraalVM Enterprise Edition: 20.3.5, 21.3.1 and 22.0.0.2. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise
    Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in
    unauthorized access to critical data or complete access to all Oracle Java SE, Oracle GraalVM Enterprise
    Edition accessible data. Note: This vulnerability applies to Java deployments, typically in clients
    running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code
    (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability
    can also be exploited by using APIs in the specified Component, e.g., through a web service which supplies
    data to the APIs. (CVE-2022-21476)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: JNDI). Supported versions that are affected are Oracle Java SE: 7u331, 8u321, 11.0.14, 17.0.2,
    18; Oracle GraalVM Enterprise Edition: 20.3.5, 21.3.1 and 22.0.0.2. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE,
    Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized
    update, insert or delete access to some of Oracle Java SE, Oracle GraalVM Enterprise Edition accessible
    data. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java
    Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes
    from the internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by
    using APIs in the specified Component, e.g., through a web service which supplies data to the APIs.
    (CVE-2022-21496)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191912");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194931");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198670");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198671");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198672");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198673");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198674");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198675");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201643");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-July/011645.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?37043a7b");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-35561");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21299");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21426");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21434");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21443");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21449");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21476");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21496");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21496");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-21476");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_1-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_1-ibm-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_1-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_1-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_1-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3|4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP2/3/4/5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'java-1_7_1-ibm-1.7.1_sr5.10-38.71.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'java-1_7_1-ibm-alsa-1.7.1_sr5.10-38.71.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'java-1_7_1-ibm-devel-1.7.1_sr5.10-38.71.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'java-1_7_1-ibm-jdbc-1.7.1_sr5.10-38.71.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'java-1_7_1-ibm-plugin-1.7.1_sr5.10-38.71.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'java-1_7_1-ibm-1.7.1_sr5.10-38.71.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'java-1_7_1-ibm-alsa-1.7.1_sr5.10-38.71.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'java-1_7_1-ibm-devel-1.7.1_sr5.10-38.71.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'java-1_7_1-ibm-jdbc-1.7.1_sr5.10-38.71.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'java-1_7_1-ibm-plugin-1.7.1_sr5.10-38.71.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'java-1_7_1-ibm-1.7.1_sr5.10-38.71.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'java-1_7_1-ibm-alsa-1.7.1_sr5.10-38.71.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'java-1_7_1-ibm-devel-1.7.1_sr5.10-38.71.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'java-1_7_1-ibm-jdbc-1.7.1_sr5.10-38.71.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'java-1_7_1-ibm-plugin-1.7.1_sr5.10-38.71.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'java-1_7_1-ibm-1.7.1_sr5.10-38.71.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.3']},
    {'reference':'java-1_7_1-ibm-alsa-1.7.1_sr5.10-38.71.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.3']},
    {'reference':'java-1_7_1-ibm-devel-1.7.1_sr5.10-38.71.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.3']},
    {'reference':'java-1_7_1-ibm-jdbc-1.7.1_sr5.10-38.71.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.3']},
    {'reference':'java-1_7_1-ibm-plugin-1.7.1_sr5.10-38.71.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.3']},
    {'reference':'java-1_7_1-ibm-1.7.1_sr5.10-38.71.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'java-1_7_1-ibm-alsa-1.7.1_sr5.10-38.71.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'java-1_7_1-ibm-devel-1.7.1_sr5.10-38.71.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'java-1_7_1-ibm-jdbc-1.7.1_sr5.10-38.71.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'java-1_7_1-ibm-plugin-1.7.1_sr5.10-38.71.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-1_7_1-ibm / java-1_7_1-ibm-alsa / java-1_7_1-ibm-devel / etc');
}
