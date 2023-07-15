##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-5235.
##

include('compat.inc');

if (description)
{
  script_id(143368);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/11");

  script_cve_id(
    "CVE-2020-16012",
    "CVE-2020-26951",
    "CVE-2020-26953",
    "CVE-2020-26956",
    "CVE-2020-26958",
    "CVE-2020-26959",
    "CVE-2020-26960",
    "CVE-2020-26961",
    "CVE-2020-26965",
    "CVE-2020-26968"
  );

  script_name(english:"Oracle Linux 7 : thunderbird (ELSA-2020-5235)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has a package installed that is affected by multiple vulnerabilities as referenced in the
ELSA-2020-5235 advisory.

  - When drawing a transparent image on top of an unknown cross-origin image, the Skia library
    drawImage function took a variable amount of time depending on the content of the underlying
    image. This resulted in potential cross-origin information exposure of image content through timing side-
    channel attacks.  (CVE-2020-16012)

  - A parsing and event loading mismatch in Firefox's SVG code could have allowed load events to fire, even
    after sanitization. An attacker already capable of exploiting an XSS vulnerability in privileged internal
    pages could have used this attack to bypass our built-in sanitizer.  (CVE-2020-26951)

  - Firefox did not block execution of scripts with incorrect MIME types when the response was intercepted and
    cached through a ServiceWorker. This could lead to a cross-site script inclusion vulnerability, or a
    Content Security Policy bypass.  (CVE-2020-26958)

  - Mozilla: DoH did not filter IPv4 mapped IP Addresses (CVE-2020-26961)

  - Mozilla developers Randell Jesup, Christian Holler, Jason Kratzer, Byron Campen, and Steve Fink reported
    memory safety bugs present in Firefox 82 and Firefox ESR 78.4. Some of these bugs showed evidence of
    memory corruption and we presume that with enough effort some of these could have been exploited to run
    arbitrary code.  (CVE-2020-26968)

  - Mozilla: Fullscreen could be enabled without displaying the security UI (CVE-2020-26953)

  - In some cases, removing HTML elements during sanitization would keep existing SVG event handlers and
    therefore lead to XSS.  (CVE-2020-26956)

  - During browser shutdown, reference decrementing could have occured on a previously freed object, resulting
    in a use-after-free, memory corruption, and a potentially exploitable crash.  (CVE-2020-26959)

  - Mozilla: Potential use-after-free in uses of nsTArray (CVE-2020-26960)

  - Mozilla: Software keyboards may have remembered typed passwords (CVE-2020-26965)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2020-5235.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected thunderbird package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26968");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:thunderbird");
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
    {'reference':'thunderbird-78.5.0-1.0.1.el7_9', 'cpu':'x86_64', 'release':'7', 'allowmaj':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'thunderbird');
}