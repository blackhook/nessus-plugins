#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6183-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177476);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/30");

  script_cve_id("CVE-2023-2828", "CVE-2023-2911");
  script_xref(name:"USN", value:"6183-1");
  script_xref(name:"IAVA", value:"2023-A-0320");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 22.10 : Bind vulnerabilities (USN-6183-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 22.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-6183-1 advisory.

  - Every `named` instance configured to run as a recursive resolver maintains a cache database holding the
    responses to the queries it has recently sent to authoritative servers. The size limit for that cache
    database can be configured using the `max-cache-size` statement in the configuration file; it defaults to
    90% of the total amount of memory available on the host. When the size of the cache reaches 7/8 of the
    configured limit, a cache-cleaning algorithm starts to remove expired and/or least-recently used RRsets
    from the cache, to keep memory use below the configured limit. It has been discovered that the
    effectiveness of the cache-cleaning algorithm used in `named` can be severely diminished by querying the
    resolver for specific RRsets in a certain order, effectively allowing the configured `max-cache-size`
    limit to be significantly exceeded. This issue affects BIND 9 versions 9.11.0 through 9.16.41, 9.18.0
    through 9.18.15, 9.19.0 through 9.19.13, 9.11.3-S1 through 9.16.41-S1, and 9.18.11-S1 through 9.18.15-S1.
    (CVE-2023-2828)

  - If the `recursive-clients` quota is reached on a BIND 9 resolver configured with both `stale-answer-enable
    yes;` and `stale-answer-client-timeout 0;`, a sequence of serve-stale-related lookups could cause `named`
    to loop and terminate unexpectedly due to a stack overflow. This issue affects BIND 9 versions 9.16.33
    through 9.16.41, 9.18.7 through 9.18.15, 9.16.33-S1 through 9.16.41-S1, and 9.18.11-S1 through 9.18.15-S1.
    (CVE-2023-2911)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6183-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2911");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9-dnsutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dnsutils");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023 Canonical, Inc. / NASL script (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('20.04' >< os_release || '22.04' >< os_release || '22.10' >< os_release || '23.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 22.10 / 23.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'bind9', 'pkgver': '1:9.16.1-0ubuntu2.15'},
    {'osver': '20.04', 'pkgname': 'bind9-dnsutils', 'pkgver': '1:9.16.1-0ubuntu2.15'},
    {'osver': '20.04', 'pkgname': 'bind9-host', 'pkgver': '1:9.16.1-0ubuntu2.15'},
    {'osver': '20.04', 'pkgname': 'bind9-libs', 'pkgver': '1:9.16.1-0ubuntu2.15'},
    {'osver': '20.04', 'pkgname': 'bind9-utils', 'pkgver': '1:9.16.1-0ubuntu2.15'},
    {'osver': '20.04', 'pkgname': 'bind9utils', 'pkgver': '1:9.16.1-0ubuntu2.15'},
    {'osver': '20.04', 'pkgname': 'dnsutils', 'pkgver': '1:9.16.1-0ubuntu2.15'},
    {'osver': '22.04', 'pkgname': 'bind9', 'pkgver': '1:9.18.12-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'bind9-dev', 'pkgver': '1:9.18.12-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'bind9-dnsutils', 'pkgver': '1:9.18.12-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'bind9-host', 'pkgver': '1:9.18.12-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'bind9-libs', 'pkgver': '1:9.18.12-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'bind9-utils', 'pkgver': '1:9.18.12-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'bind9utils', 'pkgver': '1:9.18.12-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'dnsutils', 'pkgver': '1:9.18.12-0ubuntu0.22.04.2'},
    {'osver': '22.10', 'pkgname': 'bind9', 'pkgver': '1:9.18.12-0ubuntu0.22.10.2'},
    {'osver': '22.10', 'pkgname': 'bind9-dev', 'pkgver': '1:9.18.12-0ubuntu0.22.10.2'},
    {'osver': '22.10', 'pkgname': 'bind9-dnsutils', 'pkgver': '1:9.18.12-0ubuntu0.22.10.2'},
    {'osver': '22.10', 'pkgname': 'bind9-host', 'pkgver': '1:9.18.12-0ubuntu0.22.10.2'},
    {'osver': '22.10', 'pkgname': 'bind9-libs', 'pkgver': '1:9.18.12-0ubuntu0.22.10.2'},
    {'osver': '22.10', 'pkgname': 'bind9-utils', 'pkgver': '1:9.18.12-0ubuntu0.22.10.2'},
    {'osver': '22.10', 'pkgname': 'bind9utils', 'pkgver': '1:9.18.12-0ubuntu0.22.10.2'},
    {'osver': '22.10', 'pkgname': 'dnsutils', 'pkgver': '1:9.18.12-0ubuntu0.22.10.2'},
    {'osver': '23.04', 'pkgname': 'bind9', 'pkgver': '1:9.18.12-1ubuntu1.1'},
    {'osver': '23.04', 'pkgname': 'bind9-dev', 'pkgver': '1:9.18.12-1ubuntu1.1'},
    {'osver': '23.04', 'pkgname': 'bind9-dnsutils', 'pkgver': '1:9.18.12-1ubuntu1.1'},
    {'osver': '23.04', 'pkgname': 'bind9-host', 'pkgver': '1:9.18.12-1ubuntu1.1'},
    {'osver': '23.04', 'pkgname': 'bind9-libs', 'pkgver': '1:9.18.12-1ubuntu1.1'},
    {'osver': '23.04', 'pkgname': 'bind9-utils', 'pkgver': '1:9.18.12-1ubuntu1.1'},
    {'osver': '23.04', 'pkgname': 'bind9utils', 'pkgver': '1:9.18.12-1ubuntu1.1'},
    {'osver': '23.04', 'pkgname': 'dnsutils', 'pkgver': '1:9.18.12-1ubuntu1.1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind9 / bind9-dev / bind9-dnsutils / bind9-host / bind9-libs / etc');
}
