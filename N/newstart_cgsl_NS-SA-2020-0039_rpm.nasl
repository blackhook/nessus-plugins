#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0039. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(140293);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2011-3378",
    "CVE-2012-0060",
    "CVE-2012-0061",
    "CVE-2012-0815"
  );
  script_bugtraq_id(49799, 52865);

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : rpm Multiple Vulnerabilities (NS-SA-2020-0039)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has rpm packages installed that are affected by
multiple vulnerabilities:

  - RPM 4.4.x through 4.9.x, probably before 4.9.1.2, allows remote attackers to cause a denial of service
    (memory corruption) and possibly execute arbitrary code via an rpm package with crafted headers and
    offsets that are not properly handled when a package is queried or installed, related to (1) the
    regionSwab function, (2) the headerLoad function, and (3) multiple functions in rpmio/rpmpgp.c.
    (CVE-2011-3378)

  - RPM before 4.9.1.3 does not properly validate region tags, which allows remote attackers to cause a denial
    of service (crash) and possibly execute arbitrary code via an invalid region tag in a package header to
    the (1) headerLoad, (2) rpmReadSignature, or (3) headerVerify function. (CVE-2012-0060)

  - The headerLoad function in lib/header.c in RPM before 4.9.1.3 does not properly validate region tags,
    which allows user-assisted remote attackers to cause a denial of service (crash) and possibly execute
    arbitrary code via a large region size in a package header. (CVE-2012-0061)

  - The headerVerifyInfo function in lib/header.c in RPM before 4.9.1.3 allows remote attackers to cause a
    denial of service (crash) and possibly execute arbitrary code via a negative value in a region offset of a
    package header, which is not properly handled in a numeric range comparison. (CVE-2012-0815)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0039");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL rpm packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-3378");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL CORE 5.04': [
    'rpm-4.11.3-25.el7.cgslv5lite.0.1.g4ea5a22',
    'rpm-apidocs-4.11.3-25.el7.cgslv5lite.0.1.g4ea5a22',
    'rpm-build-4.11.3-25.el7.cgslv5lite.0.1.g4ea5a22',
    'rpm-build-libs-4.11.3-25.el7.cgslv5lite.0.1.g4ea5a22',
    'rpm-cron-4.11.3-25.el7.cgslv5lite.0.1.g4ea5a22',
    'rpm-debuginfo-4.11.3-25.el7.cgslv5lite.0.1.g4ea5a22',
    'rpm-devel-4.11.3-25.el7.cgslv5lite.0.1.g4ea5a22',
    'rpm-lang-4.11.3-25.el7.cgslv5lite.0.1.g4ea5a22',
    'rpm-libs-4.11.3-25.el7.cgslv5lite.0.1.g4ea5a22',
    'rpm-plugin-systemd-inhibit-4.11.3-25.el7.cgslv5lite.0.1.g4ea5a22',
    'rpm-python-4.11.3-25.el7.cgslv5lite.0.1.g4ea5a22',
    'rpm-sign-4.11.3-25.el7.cgslv5lite.0.1.g4ea5a22'
  ],
  'CGSL MAIN 5.04': [
    'rpm-4.11.3-25.el7.cgslv5.0.1.g8473ede',
    'rpm-apidocs-4.11.3-25.el7.cgslv5.0.1.g8473ede',
    'rpm-build-4.11.3-25.el7.cgslv5.0.1.g8473ede',
    'rpm-build-libs-4.11.3-25.el7.cgslv5.0.1.g8473ede',
    'rpm-cron-4.11.3-25.el7.cgslv5.0.1.g8473ede',
    'rpm-debuginfo-4.11.3-25.el7.cgslv5.0.1.g8473ede',
    'rpm-devel-4.11.3-25.el7.cgslv5.0.1.g8473ede',
    'rpm-libs-4.11.3-25.el7.cgslv5.0.1.g8473ede',
    'rpm-plugin-systemd-inhibit-4.11.3-25.el7.cgslv5.0.1.g8473ede',
    'rpm-python-4.11.3-25.el7.cgslv5.0.1.g8473ede',
    'rpm-sign-4.11.3-25.el7.cgslv5.0.1.g8473ede'
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rpm');
}


