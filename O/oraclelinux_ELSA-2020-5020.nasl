##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-5020.
##

include('compat.inc');

if (description)
{
  script_id(142746);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/13");

  script_cve_id("CVE-2020-1935");

  script_name(english:"Oracle Linux 7 : tomcat (ELSA-2020-5020)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2020-5020 advisory.

  - In Apache Tomcat 9.0.0.M1 to 9.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99 the HTTP header parsing code used
    an approach to end-of-line parsing that allowed some invalid HTTP headers to be parsed as valid. This led
    to a possibility of HTTP Request Smuggling if Tomcat was located behind a reverse proxy that incorrectly
    handled the invalid Transfer-Encoding header in a particular manner. Such a reverse proxy is considered
    unlikely. (CVE-2020-1935)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2020-5020.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1935");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat-el-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat-jsp-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat-jsvc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat-servlet-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat-webapps");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

pkgs = [
    {'reference':'tomcat-7.0.76-16.el7_9', 'release':'7'},
    {'reference':'tomcat-admin-webapps-7.0.76-16.el7_9', 'release':'7'},
    {'reference':'tomcat-docs-webapp-7.0.76-16.el7_9', 'release':'7'},
    {'reference':'tomcat-el-2.2-api-7.0.76-16.el7_9', 'release':'7'},
    {'reference':'tomcat-javadoc-7.0.76-16.el7_9', 'release':'7'},
    {'reference':'tomcat-jsp-2.2-api-7.0.76-16.el7_9', 'release':'7'},
    {'reference':'tomcat-jsvc-7.0.76-16.el7_9', 'release':'7'},
    {'reference':'tomcat-lib-7.0.76-16.el7_9', 'release':'7'},
    {'reference':'tomcat-servlet-3.0-api-7.0.76-16.el7_9', 'release':'7'},
    {'reference':'tomcat-webapps-7.0.76-16.el7_9', 'release':'7'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'tomcat / tomcat-admin-webapps / tomcat-docs-webapp / etc');
}