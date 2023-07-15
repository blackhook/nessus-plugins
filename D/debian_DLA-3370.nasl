#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3370. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(173714);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/30");

  script_cve_id(
    "CVE-2022-23468",
    "CVE-2022-23478",
    "CVE-2022-23479",
    "CVE-2022-23483",
    "CVE-2022-23484",
    "CVE-2022-23493"
  );

  script_name(english:"Debian DLA-3370-1 : xrdp - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dla-3370 advisory.

  - xrdp is an open source project which provides a graphical login to remote machines using Microsoft Remote
    Desktop Protocol (RDP). xrdp < v0.9.21 contain a buffer over flow in xrdp_login_wnd_create() function.
    There are no known workarounds for this issue. Users are advised to upgrade. (CVE-2022-23468)

  - xrdp is an open source project which provides a graphical login to remote machines using Microsoft Remote
    Desktop Protocol (RDP). xrdp < v0.9.21 contain a Out of Bound Write in
    xrdp_mm_trans_process_drdynvc_channel_open() function. There are no known workarounds for this issue.
    Users are advised to upgrade. (CVE-2022-23478)

  - xrdp is an open source project which provides a graphical login to remote machines using Microsoft Remote
    Desktop Protocol (RDP). xrdp < v0.9.21 contain a buffer over flow in xrdp_mm_chan_data_in() function.
    There are no known workarounds for this issue. Users are advised to upgrade. (CVE-2022-23479)

  - xrdp is an open source project which provides a graphical login to remote machines using Microsoft Remote
    Desktop Protocol (RDP). xrdp < v0.9.21 contain a Out of Bound Read in libxrdp_send_to_channel() function.
    There are no known workarounds for this issue. Users are advised to upgrade. (CVE-2022-23483)

  - xrdp is an open source project which provides a graphical login to remote machines using Microsoft Remote
    Desktop Protocol (RDP). xrdp < v0.9.21 contain a Integer Overflow in
    xrdp_mm_process_rail_update_window_text() function. There are no known workarounds for this issue. Users
    are advised to upgrade. (CVE-2022-23484)

  - xrdp is an open source project which provides a graphical login to remote machines using Microsoft Remote
    Desktop Protocol (RDP). xrdp < v0.9.21 contain a Out of Bound Read in
    xrdp_mm_trans_process_drdynvc_channel_close() function. There are no known workarounds for this issue.
    Users are advised to upgrade. (CVE-2022-23493)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/xrdp");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3370");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23468");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23478");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23479");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23483");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23484");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23493");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/xrdp");
  script_set_attribute(attribute:"solution", value:
"Upgrade the xrdp packages.

For Debian 10 buster, these problems have been fixed in version 0.9.9-1+deb10u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23484");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xrdp");
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
    {'release': '10.0', 'prefix': 'xrdp', 'reference': '0.9.9-1+deb10u2'}
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
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'xrdp');
}
