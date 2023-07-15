#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-9f3938e10d
#

include('compat.inc');

if (description)
{
  script_id(178054);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2023-35934");
  script_xref(name:"FEDORA", value:"2023-9f3938e10d");

  script_name(english:"Fedora 38 : yt-dlp (2023-9f3938e10d)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 38 host has a package installed that is affected by a vulnerability as referenced in the
FEDORA-2023-9f3938e10d advisory.

  - yt-dlp is a command-line program to download videos from video sites. During file downloads, yt-dlp or the
    external downloaders that yt-dlp employs may leak cookies on HTTP redirects to a different host, or leak
    them when the host for download fragments differs from their parent manifest's host. This vulnerable
    behavior is present in yt-dlp prior to 2023.07.06 and nightly 2023.07.06.185519. All native and external
    downloaders are affected, except for `curl` and `httpie` (version 3.1.0 or later). At the file download
    stage, all cookies are passed by yt-dlp to the file downloader as a `Cookie` header, thereby losing their
    scope. This also occurs in yt-dlp's info JSON output, which may be used by external tools. As a result,
    the downloader or external tool may indiscriminately send cookies with requests to domains or paths for
    which the cookies are not scoped. yt-dlp version 2023.07.06 and nightly 2023.07.06.185519 fix this issue
    by removing the `Cookie` header upon HTTP redirects; having native downloaders calculate the `Cookie`
    header from the cookiejar, utilizing external downloaders' built-in support for cookies instead of passing
    them as header arguments, disabling HTTP redirectiong if the external downloader does not have proper
    cookie support, processing cookies passed as HTTP headers to limit their scope, and having a separate
    field for cookies in the info dict storing more information about scoping Some workarounds are available
    for those who are unable to upgrade. Avoid using cookies and user authentication methods. While extractors
    may set custom cookies, these usually do not contain sensitive information. Alternatively, avoid using
    `--load-info-json`. Or, if authentication is a must: verify the integrity of download links from unknown
    sources in browser (including redirects) before passing them to yt-dlp; use `curl` as external downloader,
    since it is not impacted; and/or avoid fragmented formats such as HLS/m3u8, DASH/mpd and ISM.
    (CVE-2023-35934)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-9f3938e10d");
  script_set_attribute(attribute:"solution", value:
"Update the affected yt-dlp package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-35934");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:38");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yt-dlp");
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
if (! preg(pattern:"^38([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 38', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'yt-dlp-2023.07.06-1.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'yt-dlp');
}
