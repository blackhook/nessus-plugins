#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2022:7519.
##

include('compat.inc');

if (description)
{
  script_id(167790);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id(
    "CVE-2021-23648",
    "CVE-2022-21673",
    "CVE-2022-21702",
    "CVE-2022-21703",
    "CVE-2022-21713"
  );
  script_xref(name:"RLSA", value:"2022:7519");

  script_name(english:"Rocky Linux 8 : grafana (RLSA-2022:7519)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2022:7519 advisory.

  - Grafana is an open-source platform for monitoring and observability. Affected versions are subject to a
    cross site request forgery vulnerability which allows attackers to elevate their privileges by mounting
    cross-origin attacks against authenticated high-privilege Grafana users (for example, Editors or Admins).
    An attacker can exploit this vulnerability for privilege escalation by tricking an authenticated user into
    inviting the attacker as a new user with high privileges. Users are advised to upgrade as soon as
    possible. There are no known workarounds for this issue. (CVE-2022-21703)

  - The package @braintree/sanitize-url before 6.0.0 are vulnerable to Cross-site Scripting (XSS) due to
    improper sanitization in sanitizeUrl function. (CVE-2021-23648)

  - Grafana is an open-source platform for monitoring and observability. In affected versions when a data
    source has the Forward OAuth Identity feature enabled, sending a query to that datasource with an API
    token (and no other user credentials) will forward the OAuth Identity of the most recently logged-in user.
    This can allow API token holders to retrieve data for which they may not have intended access. This attack
    relies on the Grafana instance having data sources that support the Forward OAuth Identity feature, the
    Grafana instance having a data source with the Forward OAuth Identity feature toggled on, the Grafana
    instance having OAuth enabled, and the Grafana instance having usable API keys. This issue has been
    patched in versions 7.5.13 and 8.3.4. (CVE-2022-21673)

  - Grafana is an open-source platform for monitoring and observability. In affected versions an attacker
    could serve HTML content thru the Grafana datasource or plugin proxy and trick a user to visit this HTML
    page using a specially crafted link and execute a Cross-site Scripting (XSS) attack. The attacker could
    either compromise an existing datasource for a specific Grafana instance or either set up its own public
    service and instruct anyone to set it up in their Grafana instance. To be impacted, all of the following
    must be applicable. For the data source proxy: A Grafana HTTP-based datasource configured with Server as
    Access Mode and a URL set, the attacker has to be in control of the HTTP server serving the URL of above
    datasource, and a specially crafted link pointing at the attacker controlled data source must be clicked
    on by an authenticated user. For the plugin proxy: A Grafana HTTP-based app plugin configured and enabled
    with a URL set, the attacker has to be in control of the HTTP server serving the URL of above app, and a
    specially crafted link pointing at the attacker controlled plugin must be clocked on by an authenticated
    user. For the backend plugin resource: An attacker must be able to navigate an authenticated user to a
    compromised plugin through a crafted link. Users are advised to update to a patched version. There are no
    known workarounds for this vulnerability. (CVE-2022-21702)

  - Grafana is an open-source platform for monitoring and observability. Affected versions of Grafana expose
    multiple API endpoints which do not properly handle user authorization. `/teams/:teamId` will allow an
    authenticated attacker to view unintended data by querying for the specific team ID, `/teams/:search` will
    allow an authenticated attacker to search for teams and see the total number of available teams, including
    for those teams that the user does not have access to, and `/teams/:teamId/members` when editors_can_admin
    flag is enabled, an authenticated attacker can see unintended data by querying for the specific team ID.
    Users are advised to upgrade as soon as possible. There are no known workarounds for this issue.
    (CVE-2022-21713)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2022:7519");
  script_set_attribute(attribute:"solution", value:
"Update the affected grafana and / or grafana-debuginfo packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21703");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:grafana");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:grafana-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'grafana-7.5.15-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grafana-7.5.15-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grafana-debuginfo-7.5.15-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grafana-debuginfo-7.5.15-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'grafana / grafana-debuginfo');
}
