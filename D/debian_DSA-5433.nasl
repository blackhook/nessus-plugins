#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5433. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(177478);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2023-3138");

  script_name(english:"Debian DSA-5433-1 : libx11 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 / 12 host has packages installed that are affected by a vulnerability as referenced in the dsa-5433
advisory.

  - The X.Org project reports: The functions in src/InitExt.c in libX11 prior to 1.8.6 do not check
    that the values provided for the Request, Event, or Error IDs are             within the bounds of the
    arrays that those functions write to, using             those IDs as array indexes.  Instead they trusted
    that they were called             with values provided by an Xserver that was adhering to the bounds
    specified in the X11 protocol, as all X servers provided by X.Org do. As the protocol only specifies a
    single byte for these values, an             out-of-bounds value provided by a malicious server (or a
    malicious             proxy-in-the-middle) can only overwrite other portions of the Display
    structure and not write outside the bounds of the Display structure             itself.  Testing has found
    it is possible to at least cause the client             to crash with this memory corruption.
    (CVE-2023-3138)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1038133");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/libx11");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5433");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-3138");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/libx11");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/libx11");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libx11 packages.

For the stable distribution (bookworm), this problem has been fixed in version 2");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3138");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libx11-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libx11-6-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libx11-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libx11-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libx11-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libx11-xcb-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libx11-xcb1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
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
if (! preg(pattern:"^(11)\.[0-9]+|^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0 / 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'libx11-6', 'reference': '2:1.7.2-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libx11-6-udeb', 'reference': '2:1.7.2-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libx11-data', 'reference': '2:1.7.2-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libx11-dev', 'reference': '2:1.7.2-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libx11-doc', 'reference': '2:1.7.2-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libx11-xcb-dev', 'reference': '2:1.7.2-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libx11-xcb1', 'reference': '2:1.7.2-1+deb11u1'},
    {'release': '12.0', 'prefix': 'libx11-6', 'reference': '2:1.8.4-2+deb12u1'},
    {'release': '12.0', 'prefix': 'libx11-6-udeb', 'reference': '2:1.8.4-2+deb12u1'},
    {'release': '12.0', 'prefix': 'libx11-data', 'reference': '2:1.8.4-2+deb12u1'},
    {'release': '12.0', 'prefix': 'libx11-dev', 'reference': '2:1.8.4-2+deb12u1'},
    {'release': '12.0', 'prefix': 'libx11-doc', 'reference': '2:1.8.4-2+deb12u1'},
    {'release': '12.0', 'prefix': 'libx11-xcb-dev', 'reference': '2:1.8.4-2+deb12u1'},
    {'release': '12.0', 'prefix': 'libx11-xcb1', 'reference': '2:1.8.4-2+deb12u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libx11-6 / libx11-6-udeb / libx11-data / libx11-dev / libx11-doc / etc');
}
