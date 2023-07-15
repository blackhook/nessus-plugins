#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-2b7eeaaee5
#

include('compat.inc');

if (description)
{
  script_id(177358);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/16");
  script_xref(name:"FEDORA", value:"2023-2b7eeaaee5");

  script_name(english:"Fedora 37 : php (2023-2b7eeaaee5)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 37 host has a package installed that is affected by a vulnerability as referenced in the
FEDORA-2023-2b7eeaaee5 advisory.

  - **PHP version 8.1.20** (08 Jun 2023)  **Core:**  * Fixed bug [GH-9068](https://github.com/php/php-
    src/issues/9068) (Conditional jump or move depends on uninitialised value(s)). (nielsdos) * Fixed bug
    [GH-11189](https://github.com/php/php-src/issues/11189) (Exceeding memory limit in zend_hash_do_resize
    leaves the array in an invalid state). (Bob) * Fixed bug [GH-11222](https://github.com/php/php-
    src/issues/11222) (foreach by-ref may jump over keys during a rehash). (Bob)  **Date:**  * Fixed bug
    [GH-11281](https://github.com/php/php-src/issues/11281) (DateTimeZone::getName() does not include seconds
    in offset). (nielsdos)  **Exif:**  * Fixed bug [GH-10834](https://github.com/php/php-src/issues/10834)
    (exif_read_data() cannot read smaller stream wrapper chunk sizes). (nielsdos)  **FPM:**  * Fixed bug
    [GH-10461](https://github.com/php/php-src/issues/10461) (PHP-FPM segfault due to after free usage of
    child->ev_std(out|err)). (Jakub Zelenka) * Fixed bug php#64539 (FPM status page: query_string not properly
    JSON encoded). (Jakub Zelenka) * Fixed memory leak for invalid primary script file handle. (Jakub Zelenka)
    **Hash:**  * Fixed bug [GH-11180](https://github.com/php/php-src/issues/11180) (hash_file() appears to be
    restricted to 3 arguments). (nielsdos)  **LibXML:**  * Fixed bug [GH-11160](https://github.com/php/php-
    src/issues/11160) (Few tests failed building with new libxml 2.11.0). (nielsdos)  **Opcache:**  * Fixed
    bug [GH-11134](https://github.com/php/php-src/issues/11134) (Incorrect match default branch optimization).
    (ilutov) * Fixed too wide OR and AND range inference. (nielsdos) * Fixed bug
    [GH-11245](https://github.com/php/php-src/issues/11245) (In some specific cases SWITCH with one default
    statement will cause segfault). (nielsdos)  **PGSQL:**  * Fixed parameter parsing of pg_lo_export().
    (kocsismate)  **Phar:**  * Fixed bug [GH-11099](https://github.com/php/php-src/issues/11099) (Generating
    phar.php during cross-compile can't be done). (peter279k)  **Soap:**  * Fixed bug
    [GHSA-76gg-c692-v2mw](https://github.com/php/php-src/security/advisories/GHSA-76gg-c692-v2mw) (Missing
    error check and insufficient random bytes in HTTP Digest authentication for SOAP). (nielsdos, timwolla) *
    Fixed bug [GH-8426](https://github.com/php/php-src/issues/8426) (make test fail while soap extension
    build). (nielsdos)  **SPL:**  * Fixed bug [GH-11178](https://github.com/php/php-src/issues/11178)
    (Segmentation fault in spl_array_it_get_current_data (PHP 8.1.18)). (nielsdos)  **Standard:**  * Fixed bug
    [GH-11138](https://github.com/php/php-src/issues/11138) (move_uploaded_file() emits open_basedir warning
    for source file). (ilutov) * Fixed bug [GH-11274](https://github.com/php/php-src/issues/11274) (POST/PATCH
    request switches to GET after a HTTP 308 redirect). (nielsdos)  **Streams:**  * Fixed bug
    [GH-10031](https://github.com/php/php-src/issues/10031) ([Stream] STREAM_NOTIFY_PROGRESS over HTTP emitted
    irregularly for last chunk of data). (nielsdos) * Fixed bug [GH-11175](https://github.com/php/php-
    src/issues/11175) (Stream Socket Timeout). (nielsdos) * Fixed bug [GH-11177](https://github.com/php/php-
    src/issues/11177) (ASAN UndefinedBehaviorSanitizer when timeout = -1 passed to
    stream_socket_accept/stream_socket_client). (nielsdos)  (FEDORA-2023-2b7eeaaee5)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-2b7eeaaee5");
  script_set_attribute(attribute:"solution", value:
"Update the affected php package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^37([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 37', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'php-8.1.20-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'php');
}
