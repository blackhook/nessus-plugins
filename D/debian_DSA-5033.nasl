#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5033. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156442);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/12/31");

  script_cve_id(
    "CVE-2021-3907",
    "CVE-2021-3909",
    "CVE-2021-43114",
    "CVE-2021-43173"
  );

  script_name(english:"Debian DSA-5033-1 : fort-validator - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dsa-5033 advisory.

  - OctoRPKI does not escape a URI with a filename containing .., this allows a repository to create a file,
    (ex. rsync://example.org/repo/../../etc/cron.daily/evil.roa), which would then be written to disk outside
    the base cache folder. This could allow for remote code execution on the host machine OctoRPKI is running
    on. (CVE-2021-3907)

  - OctoRPKI does not limit the length of a connection, allowing for a slowloris DOS attack to take place
    which makes OctoRPKI wait forever. Specifically, the repository that OctoRPKI sends HTTP requests to will
    keep the connection open for a day before a response is returned, but does keep drip feeding new bytes to
    keep the connection alive. (CVE-2021-3909)

  - FORT Validator versions prior to 1.5.2 will crash if an RPKI CA publishes an X.509 EE certificate. This
    will lead to RTR clients such as BGP routers to lose access to the RPKI VRP data set, effectively
    disabling Route Origin Validation. (CVE-2021-43114)

  - In NLnet Labs Routinator prior to 0.10.2, a validation run can be delayed significantly by an RRDP
    repository by not answering but slowly drip-feeding bytes to keep the connection alive. This can be used
    to effectively stall validation. While Routinator has a configurable time-out value for RRDP connections,
    this time-out was only applied to individual read or write operations rather than the complete request.
    Thus, if an RRDP repository sends a little bit of data before that time-out expired, it can continuously
    extend the time it takes for the request to finish. Since validation will only continue once the update of
    an RRDP repository has concluded, this delay will cause validation to stall, leading to Routinator
    continuing to serve the old data set or, if in the initial validation run directly after starting, never
    serve any data at all. (CVE-2021-43173)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/fort-validator
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a04ffe16");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2021/dsa-5033");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3907");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3909");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43114");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43173");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/fort-validator");
  script_set_attribute(attribute:"solution", value:
"Upgrade the fort-validator packages.

For the stable distribution (bullseye), these problems have been fixed in version 1.5.3-1~deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3907");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fort-validator");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'fort-validator', 'reference': '1.5.3-1~deb11u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'fort-validator');
}
