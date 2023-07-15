#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154276);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2021-35550",
    "CVE-2021-35556",
    "CVE-2021-35559",
    "CVE-2021-35561",
    "CVE-2021-35564",
    "CVE-2021-35565",
    "CVE-2021-35567",
    "CVE-2021-35578",
    "CVE-2021-35586",
    "CVE-2021-35588",
    "CVE-2021-35603"
  );
  script_xref(name:"RHSA", value:"RHSA-2021:3889");

  script_name(english:"Scientific Linux Security Update : java-1.8.0-openjdk on SL7.x i686/x86_64 (2021:3889)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Scientific Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Scientific Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SLSA-2021:3889-1 advisory.

  - OpenJDK: Loop in HttpsServer triggered during TLS session close (JSSE, 8254967) (CVE-2021-35565)

  - OpenJDK: Incorrect principal selection when using Kerberos Constrained Delegation (Libraries, 8266689)
    (CVE-2021-35567)

  - OpenJDK: Weak ciphers preferred over stronger ones for TLS (JSSE, 8264210) (CVE-2021-35550)

  - OpenJDK: Excessive memory allocation in RTFParser (Swing, 8265167) (CVE-2021-35556)

  - OpenJDK: Excessive memory allocation in RTFReader (Swing, 8265580) (CVE-2021-35559)

  - OpenJDK: Excessive memory allocation in HashMap and HashSet (Utility, 8266097) (CVE-2021-35561)

  - OpenJDK: Certificates with end dates too far in the future can corrupt keystore (Keytool, 8266137)
    (CVE-2021-35564)

  - OpenJDK: Unexpected exception raised during TLS handshake (JSSE, 8267729) (CVE-2021-35578)

  - OpenJDK: Excessive memory allocation in BMPImageReader (ImageIO, 8267735) (CVE-2021-35586)

  - OpenJDK: Incomplete validation of inner class references in ClassFileParser (Hotspot, 8268071)
    (CVE-2021-35588)

  - OpenJDK: Non-constant comparison during TLS handshakes (JSSE, 8269618) (CVE-2021-35603)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.scientificlinux.org/category/sl-errata/slsa-20213889-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35550");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-35567");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fermilab:scientific_linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-javadoc-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-src");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Scientific Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/RedHat/release');
if (isnull(release) || 'Scientific Linux' >!< release) audit(AUDIT_OS_NOT, 'Scientific Linux');
var os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Scientific Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Scientific Linux 7.x', 'Scientific Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Scientific Linux', cpu);

var pkgs = [
    {'reference':'java-1.8.0-openjdk-1.8.0.312.b07-1.el7_9', 'cpu':'i686', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-1.8.0.312.b07-1.el7_9', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-accessibility-1.8.0.312.b07-1.el7_9', 'cpu':'i686', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-accessibility-1.8.0.312.b07-1.el7_9', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-debuginfo-1.8.0.312.b07-1.el7_9', 'cpu':'i686', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-debuginfo-1.8.0.312.b07-1.el7_9', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-demo-1.8.0.312.b07-1.el7_9', 'cpu':'i686', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-demo-1.8.0.312.b07-1.el7_9', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-devel-1.8.0.312.b07-1.el7_9', 'cpu':'i686', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-devel-1.8.0.312.b07-1.el7_9', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-headless-1.8.0.312.b07-1.el7_9', 'cpu':'i686', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-headless-1.8.0.312.b07-1.el7_9', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-javadoc-1.8.0.312.b07-1.el7_9', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-javadoc-zip-1.8.0.312.b07-1.el7_9', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-src-1.8.0.312.b07-1.el7_9', 'cpu':'i686', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-src-1.8.0.312.b07-1.el7_9', 'cpu':'x86_64', 'release':'SL7', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-1.8.0-openjdk / java-1.8.0-openjdk-accessibility / java-1.8.0-openjdk-debuginfo / etc');
}
