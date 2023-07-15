#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-9465.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153665);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id(
    "CVE-2021-28651",
    "CVE-2021-28652",
    "CVE-2021-31806",
    "CVE-2021-31807",
    "CVE-2021-31808",
    "CVE-2021-33620"
  );

  script_name(english:"Oracle Linux 7 : squid (ELSA-2021-9465)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2021-9465 advisory.

  - An issue was discovered in Squid before 4.15 and 5.x before 5.0.6. Due to a buffer-management bug, it
    allows a denial of service. When resolving a request with the urn: scheme, the parser leaks a small amount
    of memory. However, there is an unspecified attack methodology that can easily trigger a large amount of
    memory consumption. (CVE-2021-28651)

  - An issue was discovered in Squid before 4.15 and 5.x before 5.0.6. Due to a memory-management bug, it is
    vulnerable to a Denial of Service attack (against all clients using the proxy) via HTTP Range request
    processing. (CVE-2021-31806)

  - An issue was discovered in Squid before 4.15 and 5.x before 5.0.6. An integer overflow problem allows a
    remote server to achieve Denial of Service when delivering responses to HTTP Range requests. The issue
    trigger is a header that can be expected to exist in HTTP traffic without any malicious intent.
    (CVE-2021-31807)

  - An issue was discovered in Squid before 4.15 and 5.x before 5.0.6. Due to an input-validation bug, it is
    vulnerable to a Denial of Service attack (against all clients using the proxy). A client sends an HTTP
    Range request to trigger this. (CVE-2021-31808)

  - An issue was discovered in Squid before 4.15 and 5.x before 5.0.6. Due to incorrect parser validation, it
    allows a Denial of Service attack against the Cache Manager API. This allows a trusted client to trigger
    memory leaks that. over time, lead to a Denial of Service via an unspecified short query string. This
    attack is limited to clients with Cache Manager API access privilege. (CVE-2021-28652)

  - Squid before 4.15 and 5.x before 5.0.6 allows remote servers to cause a denial of service (affecting
    availability to all clients) via an HTTP response. The issue trigger is a header that can be expected to
    exist in HTTP traffic without any malicious intent by the server. (CVE-2021-33620)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-9465.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected squid, squid-migration-script and / or squid-sysvinit packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28651");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:squid-migration-script");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:squid-sysvinit");
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

var pkgs = [
    {'reference':'squid-3.5.20-17.0.1.el7_9.6', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'squid-3.5.20-17.0.1.el7_9.6', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'squid-migration-script-3.5.20-17.0.1.el7_9.6', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'squid-migration-script-3.5.20-17.0.1.el7_9.6', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'squid-sysvinit-3.5.20-17.0.1.el7_9.6', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'squid-sysvinit-3.5.20-17.0.1.el7_9.6', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'squid / squid-migration-script / squid-sysvinit');
}
