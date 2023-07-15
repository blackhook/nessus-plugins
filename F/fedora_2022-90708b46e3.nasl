#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2022-90708b46e3
#

include('compat.inc');

if (description)
{
  script_id(169143);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/22");

  script_cve_id(
    "CVE-2022-39955",
    "CVE-2022-39956",
    "CVE-2022-39957",
    "CVE-2022-39958"
  );
  script_xref(name:"FEDORA", value:"2022-90708b46e3");

  script_name(english:"Fedora 36 : mod_security / mod_security_crs (2022-90708b46e3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 36 host has packages installed that are affected by multiple vulnerabilities as referenced in the
FEDORA-2022-90708b46e3 advisory.

  - The OWASP ModSecurity Core Rule Set (CRS) is affected by a partial rule set bypass by submitting a
    specially crafted HTTP Content-Type header field that indicates multiple character encoding schemes. A
    vulnerable back-end can potentially be exploited by declaring multiple Content-Type charset names and
    therefore bypassing the configurable CRS Content-Type header charset allow list. An encoded payload can
    bypass CRS detection this way and may then be decoded by the backend. The legacy CRS versions 3.0.x and
    3.1.x are affected, as well as the currently supported versions 3.2.1 and 3.3.2. Integrators and users are
    advised to upgrade to 3.2.2 and 3.3.3 respectively. (CVE-2022-39955)

  - The OWASP ModSecurity Core Rule Set (CRS) is affected by a partial rule set bypass for HTTP multipart
    requests by submitting a payload that uses a character encoding scheme via the Content-Type or the
    deprecated Content-Transfer-Encoding multipart MIME header fields that will not be decoded and inspected
    by the web application firewall engine and the rule set. The multipart payload will therefore bypass
    detection. A vulnerable backend that supports these encoding schemes can potentially be exploited. The
    legacy CRS versions 3.0.x and 3.1.x are affected, as well as the currently supported versions 3.2.1 and
    3.3.2. Integrators and users are advised upgrade to 3.2.2 and 3.3.3 respectively. The mitigation against
    these vulnerabilities depends on the installation of the latest ModSecurity version (v2.9.6 / v3.0.8).
    (CVE-2022-39956)

  - The OWASP ModSecurity Core Rule Set (CRS) is affected by a response body bypass. A client can issue an
    HTTP Accept header field containing an optional charset parameter in order to receive the response in an
    encoded form. Depending on the charset, this response can not be decoded by the web application
    firewall. A restricted resource, access to which would ordinarily be detected, may therefore bypass
    detection. The legacy CRS versions 3.0.x and 3.1.x are affected, as well as the currently supported
    versions 3.2.1 and 3.3.2. Integrators and users are advised to upgrade to 3.2.2 and 3.3.3 respectively.
    (CVE-2022-39957)

  - The OWASP ModSecurity Core Rule Set (CRS) is affected by a response body bypass to sequentially exfiltrate
    small and undetectable sections of data by repeatedly submitting an HTTP Range header field with a small
    byte range. A restricted resource, access to which would ordinarily be detected, may be exfiltrated from
    the backend, despite being protected by a web application firewall that uses CRS. Short subsections of a
    restricted resource may bypass pattern matching techniques and allow undetected access. The legacy CRS
    versions 3.0.x and 3.1.x are affected, as well as the currently supported versions 3.2.1 and 3.3.2.
    Integrators and users are advised to upgrade to 3.2.2 and 3.3.3 respectively and to configure a CRS
    paranoia level of 3 or higher. (CVE-2022-39958)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2022-90708b46e3");
  script_set_attribute(attribute:"solution", value:
"Update the affected mod_security and / or mod_security_crs packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-39956");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:36");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mod_security");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mod_security_crs");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^36([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 36', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'mod_security-2.9.6-1.fc36', 'release':'FC36', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_security_crs-3.3.4-1.fc36', 'release':'FC36', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'mod_security / mod_security_crs');
}
