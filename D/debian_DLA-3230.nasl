#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3230. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(168485);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/08");

  script_cve_id(
    "CVE-2021-41182",
    "CVE-2021-41183",
    "CVE-2021-41184",
    "CVE-2022-31160"
  );

  script_name(english:"Debian DLA-3230-1 : jqueryui - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3230 advisory.

  - jQuery-UI is the official jQuery user interface library. Prior to version 1.13.0, accepting the value of
    the `altField` option of the Datepicker widget from untrusted sources may execute untrusted code. The
    issue is fixed in jQuery UI 1.13.0. Any string value passed to the `altField` option is now treated as a
    CSS selector. A workaround is to not accept the value of the `altField` option from untrusted sources.
    (CVE-2021-41182)

  - jQuery-UI is the official jQuery user interface library. Prior to version 1.13.0, accepting the value of
    various `*Text` options of the Datepicker widget from untrusted sources may execute untrusted code. The
    issue is fixed in jQuery UI 1.13.0. The values passed to various `*Text` options are now always treated as
    pure text, not HTML. A workaround is to not accept the value of the `*Text` options from untrusted
    sources. (CVE-2021-41183)

  - jQuery-UI is the official jQuery user interface library. Prior to version 1.13.0, accepting the value of
    the `of` option of the `.position()` util from untrusted sources may execute untrusted code. The issue is
    fixed in jQuery UI 1.13.0. Any string value passed to the `of` option is now treated as a CSS selector. A
    workaround is to not accept the value of the `of` option from untrusted sources. (CVE-2021-41184)

  - jQuery UI is a curated set of user interface interactions, effects, widgets, and themes built on top of
    jQuery. Versions prior to 1.13.2 are potentially vulnerable to cross-site scripting. Initializing a
    checkboxradio widget on an input enclosed within a label makes that parent label contents considered as
    the input label. Calling `.checkboxradio( refresh )` on such a widget and the initial HTML contained
    encoded HTML entities will make them erroneously get decoded. This can lead to potentially executing
    JavaScript code. The bug has been patched in jQuery UI 1.13.2. To remediate the issue, someone who can
    change the initial HTML can wrap all the non-input contents of the `label` in a `span`. (CVE-2022-31160)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1015982");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/jqueryui");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3230");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41182");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41183");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41184");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-31160");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/jqueryui");
  script_set_attribute(attribute:"solution", value:
"Upgrade the jqueryui packages.

For Debian 10 buster, these problems have been fixed in version 1.12.1+dfsg-5+deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41184");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-31160");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjs-jquery-ui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjs-jquery-ui-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-jquery-ui");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'libjs-jquery-ui', 'reference': '1.12.1+dfsg-5+deb10u1'},
    {'release': '10.0', 'prefix': 'libjs-jquery-ui-docs', 'reference': '1.12.1+dfsg-5+deb10u1'},
    {'release': '10.0', 'prefix': 'node-jquery-ui', 'reference': '1.12.1+dfsg-5+deb10u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libjs-jquery-ui / libjs-jquery-ui-docs / node-jquery-ui');
}
