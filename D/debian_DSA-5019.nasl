#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5019. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156013);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/27");

  script_cve_id(
    "CVE-2021-22207",
    "CVE-2021-22222",
    "CVE-2021-22235",
    "CVE-2021-39920",
    "CVE-2021-39921",
    "CVE-2021-39922",
    "CVE-2021-39923",
    "CVE-2021-39924",
    "CVE-2021-39925",
    "CVE-2021-39926",
    "CVE-2021-39928",
    "CVE-2021-39929"
  );
  script_xref(name:"IAVB", value:"2021-B-0061-S");
  script_xref(name:"IAVB", value:"2021-B-0065-S");
  script_xref(name:"IAVB", value:"2021-B-0028-S");

  script_name(english:"Debian DSA-5019-1 : wireshark - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5019 advisory.

  - Excessive memory consumption in MS-WSP dissector in Wireshark 3.4.0 to 3.4.4 and 3.2.0 to 3.2.12 allows
    denial of service via packet injection or crafted capture file (CVE-2021-22207)

  - Infinite loop in DVB-S2-BB dissector in Wireshark 3.4.0 to 3.4.5 allows denial of service via packet
    injection or crafted capture file (CVE-2021-22222)

  - Crash in DNP dissector in Wireshark 3.4.0 to 3.4.6 and 3.2.0 to 3.2.14 allows denial of service via packet
    injection or crafted capture file (CVE-2021-22235)

  - NULL pointer exception in the IPPUSB dissector in Wireshark 3.4.0 to 3.4.9 allows denial of service via
    packet injection or crafted capture file (CVE-2021-39920)

  - NULL pointer exception in the Modbus dissector in Wireshark 3.4.0 to 3.4.9 and 3.2.0 to 3.2.17 allows
    denial of service via packet injection or crafted capture file (CVE-2021-39921)

  - Buffer overflow in the C12.22 dissector in Wireshark 3.4.0 to 3.4.9 and 3.2.0 to 3.2.17 allows denial of
    service via packet injection or crafted capture file (CVE-2021-39922)

  - Large loop in the PNRP dissector in Wireshark 3.4.0 to 3.4.9 and 3.2.0 to 3.2.17 allows denial of service
    via packet injection or crafted capture file (CVE-2021-39923)

  - Large loop in the Bluetooth DHT dissector in Wireshark 3.4.0 to 3.4.9 and 3.2.0 to 3.2.17 allows denial of
    service via packet injection or crafted capture file (CVE-2021-39924)

  - Buffer overflow in the Bluetooth SDP dissector in Wireshark 3.4.0 to 3.4.9 and 3.2.0 to 3.2.17 allows
    denial of service via packet injection or crafted capture file (CVE-2021-39925)

  - Buffer overflow in the Bluetooth HCI_ISO dissector in Wireshark 3.4.0 to 3.4.9 allows denial of service
    via packet injection or crafted capture file (CVE-2021-39926)

  - NULL pointer exception in the IEEE 802.11 dissector in Wireshark 3.4.0 to 3.4.9 and 3.2.0 to 3.2.17 allows
    denial of service via packet injection or crafted capture file (CVE-2021-39928)

  - Uncontrolled Recursion in the Bluetooth DHT dissector in Wireshark 3.4.0 to 3.4.9 and 3.2.0 to 3.2.17
    allows denial of service via packet injection or crafted capture file (CVE-2021-39929)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/wireshark");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2021/dsa-5019");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-22207");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-22222");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-22235");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39920");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39921");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39922");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39923");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39924");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39925");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39926");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39928");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39929");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/wireshark");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/wireshark");
  script_set_attribute(attribute:"solution", value:
"Upgrade the wireshark packages.

For the stable distribution (bullseye), these problems have been fixed in version 3.4.10-0+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39929");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwireshark-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwireshark-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwireshark11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwireshark14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwiretap-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwiretap11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwiretap8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwscodecs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwsutil-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwsutil12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwsutil9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-qt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '11.0', 'prefix': 'libwireshark-data', 'reference': '3.4.10-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libwireshark-dev', 'reference': '3.4.10-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libwireshark11', 'reference': '3.4.10-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libwireshark14', 'reference': '3.4.10-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libwiretap-dev', 'reference': '3.4.10-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libwiretap11', 'reference': '3.4.10-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libwiretap8', 'reference': '3.4.10-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libwscodecs2', 'reference': '3.4.10-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libwsutil-dev', 'reference': '3.4.10-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libwsutil12', 'reference': '3.4.10-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libwsutil9', 'reference': '3.4.10-0+deb11u1'},
    {'release': '11.0', 'prefix': 'tshark', 'reference': '3.4.10-0+deb11u1'},
    {'release': '11.0', 'prefix': 'wireshark', 'reference': '3.4.10-0+deb11u1'},
    {'release': '11.0', 'prefix': 'wireshark-common', 'reference': '3.4.10-0+deb11u1'},
    {'release': '11.0', 'prefix': 'wireshark-dev', 'reference': '3.4.10-0+deb11u1'},
    {'release': '11.0', 'prefix': 'wireshark-doc', 'reference': '3.4.10-0+deb11u1'},
    {'release': '11.0', 'prefix': 'wireshark-gtk', 'reference': '3.4.10-0+deb11u1'},
    {'release': '11.0', 'prefix': 'wireshark-qt', 'reference': '3.4.10-0+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libwireshark-data / libwireshark-dev / libwireshark11 / libwireshark14 / etc');
}
