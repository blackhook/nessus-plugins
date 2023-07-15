#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3266. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(169915);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2023-22456", "CVE-2023-22464");

  script_name(english:"Debian DLA-3266-1 : viewvc - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3266 advisory.

  - ViewVC, a browser interface for CVS and Subversion version control repositories, as a cross-site scripting
    vulnerability that affects versions prior to 1.2.2 and 1.1.29. The impact of this vulnerability is
    mitigated by the need for an attacker to have commit privileges to a Subversion repository exposed by an
    otherwise trusted ViewVC instance. The attack vector involves files with unsafe names (names that, when
    embedded into an HTML stream, would cause the browser to run unwanted code), which themselves can be
    challenging to create. Users should update to at least version 1.2.2 (if they are using a 1.2.x version of
    ViewVC) or 1.1.29 (if they are using a 1.1.x version). ViewVC 1.0.x is no longer supported, so users of
    that release lineage should implement a workaround. Users can edit their ViewVC EZT view templates to
    manually HTML-escape changed paths during rendering. Locate in your template set's `revision.ezt` file
    references to those changed paths, and wrap them with `[format html]` and `[end]`. For most users, that
    means that references to `[changes.path]` will become `[format html][changes.path][end]`. (This
    workaround should be reverted after upgrading to a patched version of ViewVC, else changed path names will
    be doubly escaped.) (CVE-2023-22456)

  - ViewVC is a browser interface for CVS and Subversion version control repositories. Versions prior to 1.2.3
    and 1.1.30 are vulnerable to cross-site scripting. The impact of this vulnerability is mitigated by the
    need for an attacker to have commit privileges to a Subversion repository exposed by an otherwise trusted
    ViewVC instance. The attack vector involves files with unsafe names (names that, when embedded into an
    HTML stream, would cause the browser to run unwanted code), which themselves can be challenging to create.
    Users should update to at least version 1.2.3 (if they are using a 1.2.x version of ViewVC) or 1.1.30 (if
    they are using a 1.1.x version). ViewVC 1.0.x is no longer supported, so users of that release lineage
    should implement one of the following workarounds. Users can edit their ViewVC EZT view templates to
    manually HTML-escape changed path copyfrom paths during rendering. Locate in your template set's
    `revision.ezt` file references to those changed paths, and wrap them with `[format html]` and `[end]`.
    For most users, that means that references to `[changes.copy_path]` will become `[format
    html][changes.copy_path][end]`. (This workaround should be reverted after upgrading to a patched version
    of ViewVC, else copyfrom path names will be doubly escaped.) (CVE-2023-22464)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3266");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-22456");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-22464");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/viewvc");
  script_set_attribute(attribute:"solution", value:
"Upgrade the viewvc packages.

For Debian 10 Buster, these problems have been fixed in version 1.1.26-1+deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22456");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:viewvc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:viewvc-query");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '10.0', 'prefix': 'viewvc', 'reference': '1.1.26-1+deb10u1'},
    {'release': '10.0', 'prefix': 'viewvc-query', 'reference': '1.1.26-1+deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'viewvc / viewvc-query');
}
