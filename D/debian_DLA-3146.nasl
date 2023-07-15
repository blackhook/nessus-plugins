#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3146. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(166004);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/01");

  script_cve_id("CVE-2022-2928", "CVE-2022-2929");

  script_name(english:"Debian DLA-3146-1 : isc-dhcp - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3146 advisory.

  - In ISC DHCP 4.4.0 -> 4.4.3, ISC DHCP 4.1-ESV-R1 -> 4.1-ESV-R16-P1, when the function
    option_code_hash_lookup() is called from add_option(), it increases the option's refcount field. However,
    there is not a corresponding call to option_dereference() to decrement the refcount field. The function
    add_option() is only used in server responses to lease query packets. Each lease query response calls this
    function for several options, so eventually, the reference counters could overflow and cause the server to
    abort. (CVE-2022-2928)

  - In ISC DHCP 1.0 -> 4.4.3, ISC DHCP 4.1-ESV-R1 -> 4.1-ESV-R16-P1 a system with access to a DHCP server,
    sending DHCP packets crafted to include fqdn labels longer than 63 bytes, could eventually cause the
    server to run out of memory. (CVE-2022-2929)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1021320");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/isc-dhcp");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3146");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2928");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2929");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/isc-dhcp");
  script_set_attribute(attribute:"solution", value:
"Upgrade the isc-dhcp packages.

For Debian 10 buster, these problems have been fixed in version 4.4.1-2+deb10u2.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2929");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-client-ddns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-relay");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-server-ldap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
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

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(10)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'isc-dhcp-client', 'reference': '4.4.1-2+deb10u2'},
    {'release': '10.0', 'prefix': 'isc-dhcp-client-ddns', 'reference': '4.4.1-2+deb10u2'},
    {'release': '10.0', 'prefix': 'isc-dhcp-common', 'reference': '4.4.1-2+deb10u2'},
    {'release': '10.0', 'prefix': 'isc-dhcp-dev', 'reference': '4.4.1-2+deb10u2'},
    {'release': '10.0', 'prefix': 'isc-dhcp-relay', 'reference': '4.4.1-2+deb10u2'},
    {'release': '10.0', 'prefix': 'isc-dhcp-server', 'reference': '4.4.1-2+deb10u2'},
    {'release': '10.0', 'prefix': 'isc-dhcp-server-ldap', 'reference': '4.4.1-2+deb10u2'}
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
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'isc-dhcp-client / isc-dhcp-client-ddns / isc-dhcp-common / etc');
}
