#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5344. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(171237);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2022-3437", "CVE-2022-45142");

  script_name(english:"Debian DSA-5344-1 : heimdal - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5344 advisory.

  - The fix for CVE-2022-3437 included changing memcmp to be constant time and a workaround for a compiler bug
    by adding != 0 comparisons to the result of memcmp. When these patches were backported to the
    heimdal-7.7.1 and heimdal-7.8.0 branches (and possibly other branches) a logic inversion sneaked in
    causing the validation of message integrity codes in gssapi/arcfour to be inverted. (CVE-2022-45142)

  - A heap-based buffer overflow vulnerability was found in Samba within the GSSAPI unwrap_des() and
    unwrap_des3() routines of Heimdal. The DES and Triple-DES decryption routines in the Heimdal GSSAPI
    library allow a length-limited write buffer overflow on malloc() allocated memory when presented with a
    maliciously small packet. This flaw allows a remote user to send specially crafted malicious data to the
    application, possibly resulting in a denial of service (DoS) attack. (CVE-2022-3437)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1030849");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/heimdal");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5344");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3437");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-45142");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/heimdal");
  script_set_attribute(attribute:"solution", value:
"Upgrade the heimdal packages.

For the stable distribution (bullseye), this problem has been fixed in version 7.7.0+dfsg-2+deb11u3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-45142");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:heimdal-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:heimdal-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:heimdal-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:heimdal-kcm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:heimdal-kdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:heimdal-multidev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:heimdal-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libasn1-8-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgssapi3-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhcrypto4-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhdb9-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libheimbase1-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libheimntlm0-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhx509-5-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkadm5clnt7-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkadm5srv8-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkafs0-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkdc2-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkrb5-26-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libotp0-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libroken18-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsl0-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwind0-heimdal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'heimdal-clients', 'reference': '7.7.0+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'heimdal-dev', 'reference': '7.7.0+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'heimdal-docs', 'reference': '7.7.0+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'heimdal-kcm', 'reference': '7.7.0+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'heimdal-kdc', 'reference': '7.7.0+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'heimdal-multidev', 'reference': '7.7.0+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'heimdal-servers', 'reference': '7.7.0+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'libasn1-8-heimdal', 'reference': '7.7.0+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'libgssapi3-heimdal', 'reference': '7.7.0+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'libhcrypto4-heimdal', 'reference': '7.7.0+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'libhdb9-heimdal', 'reference': '7.7.0+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'libheimbase1-heimdal', 'reference': '7.7.0+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'libheimntlm0-heimdal', 'reference': '7.7.0+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'libhx509-5-heimdal', 'reference': '7.7.0+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'libkadm5clnt7-heimdal', 'reference': '7.7.0+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'libkadm5srv8-heimdal', 'reference': '7.7.0+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'libkafs0-heimdal', 'reference': '7.7.0+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'libkdc2-heimdal', 'reference': '7.7.0+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'libkrb5-26-heimdal', 'reference': '7.7.0+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'libotp0-heimdal', 'reference': '7.7.0+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'libroken18-heimdal', 'reference': '7.7.0+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'libsl0-heimdal', 'reference': '7.7.0+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'libwind0-heimdal', 'reference': '7.7.0+dfsg-2+deb11u3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'heimdal-clients / heimdal-dev / heimdal-docs / heimdal-kcm / etc');
}
