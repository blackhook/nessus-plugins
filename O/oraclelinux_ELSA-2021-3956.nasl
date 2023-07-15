#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-3956.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154433);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id(
    "CVE-2021-39139",
    "CVE-2021-39140",
    "CVE-2021-39141",
    "CVE-2021-39144",
    "CVE-2021-39145",
    "CVE-2021-39146",
    "CVE-2021-39147",
    "CVE-2021-39148",
    "CVE-2021-39149",
    "CVE-2021-39150",
    "CVE-2021-39151",
    "CVE-2021-39152",
    "CVE-2021-39153",
    "CVE-2021-39154"
  );
  script_xref(name:"CEA-ID", value:"CEA-2022-0035");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/03/31");

  script_name(english:"Oracle Linux 7 : xstream (ELSA-2021-3956)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2021-3956 advisory.

  - XStream is a simple library to serialize objects to XML and back again. In affected versions this
    vulnerability may allow a remote attacker to load and execute arbitrary code from a remote host only by
    manipulating the processed input stream. A user is only affected if using the version out of the box with
    JDK 1.7u21 or below. However, this scenario can be adjusted easily to an external Xalan that works
    regardless of the version of the Java runtime. No user is affected, who followed the recommendation to
    setup XStream's security framework with a whitelist limited to the minimal required types. XStream 1.4.18
    uses no longer a blacklist by default, since it cannot be secured for general purpose. (CVE-2021-39139)

  - XStream is a simple library to serialize objects to XML and back again. In affected versions this
    vulnerability may allow a remote attacker to allocate 100% CPU time on the target system depending on CPU
    type or parallel execution of such a payload resulting in a denial of service only by manipulating the
    processed input stream. No user is affected, who followed the recommendation to setup XStream's security
    framework with a whitelist limited to the minimal required types. XStream 1.4.18 uses no longer a
    blacklist by default, since it cannot be secured for general purpose. (CVE-2021-39140)

  - XStream is a simple library to serialize objects to XML and back again. In affected versions this
    vulnerability may allow a remote attacker to load and execute arbitrary code from a remote host only by
    manipulating the processed input stream. No user is affected, who followed the recommendation to setup
    XStream's security framework with a whitelist limited to the minimal required types. XStream 1.4.18 uses
    no longer a blacklist by default, since it cannot be secured for general purpose. (CVE-2021-39141,
    CVE-2021-39145, CVE-2021-39146, CVE-2021-39147, CVE-2021-39148, CVE-2021-39149, CVE-2021-39151,
    CVE-2021-39154)

  - XStream is a simple library to serialize objects to XML and back again. In affected versions this
    vulnerability may allow a remote attacker to request data from internal resources that are not publicly
    available only by manipulating the processed input stream with a Java runtime version 14 to 8. No user is
    affected, who followed the recommendation to setup XStream's security framework with a whitelist limited
    to the minimal required types. If you rely on XStream's default blacklist of the [Security
    Framework](https://x-stream.github.io/security.html#framework), you will have to use at least version
    1.4.18. (CVE-2021-39150, CVE-2021-39152)

  - XStream is a simple library to serialize objects to XML and back again. In affected versions this
    vulnerability may allow a remote attacker has sufficient rights to execute commands of the host only by
    manipulating the processed input stream. No user is affected, who followed the recommendation to setup
    XStream's security framework with a whitelist limited to the minimal required types. XStream 1.4.18 uses
    no longer a blacklist by default, since it cannot be secured for general purpose. (CVE-2021-39144)

  - XStream is a simple library to serialize objects to XML and back again. In affected versions this
    vulnerability may allow a remote attacker to load and execute arbitrary code from a remote host only by
    manipulating the processed input stream, if using the version out of the box with Java runtime version 14
    to 8 or with JavaFX installed. No user is affected, who followed the recommendation to setup XStream's
    security framework with a whitelist limited to the minimal required types. XStream 1.4.18 uses no longer a
    blacklist by default, since it cannot be secured for general purpose. (CVE-2021-39153)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-3956.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected xstream and / or xstream-javadoc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39139");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'VMware NSX Manager XStream unauthenticated RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xstream-javadoc");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var pkgs = [
    {'reference':'xstream-1.3.1-16.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xstream-javadoc-1.3.1-16.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'xstream / xstream-javadoc');
}
