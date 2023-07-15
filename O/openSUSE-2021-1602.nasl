#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:1602-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156216);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/12/21");

  script_cve_id("CVE-2021-41177", "CVE-2021-41178", "CVE-2021-41179");

  script_name(english:"openSUSE 15 Security Update : nextcloud (openSUSE-SU-2021:1602-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:1602-1 advisory.

  - Nextcloud is an open-source, self-hosted productivity platform. Prior to versions 20.0.13, 21.0.5, and
    22.2.0, Nextcloud Server did not implement a database backend for rate-limiting purposes. Any component of
    Nextcloud using rate-limits (as as `AnonRateThrottle` or `UserRateThrottle`) was thus not rate limited on
    instances not having a memory cache backend configured. In the case of a default installation, this would
    notably include the rate-limits on the two factor codes. It is recommended that the Nextcloud Server be
    upgraded to 20.0.13, 21.0.5, or 22.2.0. As a workaround, enable a memory cache backend in `config.php`.
    (CVE-2021-41177)

  - Nextcloud is an open-source, self-hosted productivity platform. Prior to versions 20.0.13, 21.0.5, and
    22.2.0, a file traversal vulnerability makes an attacker able to download arbitrary SVG images from the
    host system, including user provided files. This could also be leveraged into a XSS/phishing attack, an
    attacker could upload a malicious SVG file that mimics the Nextcloud login form and send a specially
    crafted link to victims. The XSS risk here is mitigated due to the fact that Nextcloud employs a strict
    Content-Security-Policy disallowing execution of arbitrary JavaScript. It is recommended that the
    Nextcloud Server be upgraded to 20.0.13, 21.0.5 or 22.2.0. There are no known workarounds aside from
    upgrading. (CVE-2021-41178)

  - Nextcloud is an open-source, self-hosted productivity platform. Prior to Nextcloud Server versions
    20.0.13, 21.0.5, and 22.2.0, the Two-Factor Authentication wasn't enforced for pages marked as public. Any
    page marked as `@PublicPage` could thus be accessed with a valid user session that isn't authenticated.
    This particularly affects the Nextcloud Talk application, as this could be leveraged to gain access to any
    private chat channel without going through the Two-Factor flow. It is recommended that the Nextcloud
    Server be upgraded to 20.0.13, 21.0.5 or 22.2.0. There are no known workarounds aside from upgrading.
    (CVE-2021-41179)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192030");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192031");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YPS4NA73653ZFLPRD3JJVTUZZ4PYGDUS/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c82d8b42");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-41177");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-41178");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-41179");
  script_set_attribute(attribute:"solution", value:
"Update the affected nextcloud and / or nextcloud-apache packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41177");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nextcloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nextcloud-apache");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE15\.2|SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.2 / 15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'nextcloud-20.0.14-bp153.2.9.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nextcloud-20.0.14-bp153.2.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nextcloud-apache-20.0.14-bp153.2.9.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nextcloud-apache-20.0.14-bp153.2.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nextcloud / nextcloud-apache');
}
