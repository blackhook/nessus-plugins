#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3313. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(171394);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id(
    "CVE-2022-4345",
    "CVE-2023-0411",
    "CVE-2023-0412",
    "CVE-2023-0413",
    "CVE-2023-0415",
    "CVE-2023-0417"
  );
  script_xref(name:"IAVB", value:"2023-B-0004-S");
  script_xref(name:"IAVB", value:"2023-B-0008-S");

  script_name(english:"Debian DLA-3313-1 : wireshark - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3313 advisory.

  - Infinite loops in the BPv6, OpenFlow, and Kafka protocol dissectors in Wireshark 4.0.0 to 4.0.1 and 3.6.0
    to 3.6.9 allows denial of service via packet injection or crafted capture file (CVE-2022-4345)

  - Excessive loops in multiple dissectors in Wireshark 4.0.0 to 4.0.2 and 3.6.0 to 3.6.10 and allows denial
    of service via packet injection or crafted capture file (CVE-2023-0411)

  - TIPC dissector crash in Wireshark 4.0.0 to 4.0.2 and 3.6.0 to 3.6.10 and allows denial of service via
    packet injection or crafted capture file (CVE-2023-0412)

  - Dissection engine bug in Wireshark 4.0.0 to 4.0.2 and 3.6.0 to 3.6.10 and allows denial of service via
    packet injection or crafted capture file (CVE-2023-0413)

  - iSCSI dissector crash in Wireshark 4.0.0 to 4.0.2 and 3.6.0 to 3.6.10 and allows denial of service via
    packet injection or crafted capture file (CVE-2023-0415)

  - Memory leak in the NFS dissector in Wireshark 4.0.0 to 4.0.2 and 3.6.0 to 3.6.10 and allows denial of
    service via packet injection or crafted capture file (CVE-2023-0417)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/wireshark");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3313");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-4345");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0411");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0412");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0413");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0415");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0417");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/wireshark");
  script_set_attribute(attribute:"solution", value:
"Upgrade the wireshark packages.

For Debian 10 buster, these problems have been fixed in version 2.6.20-0+deb10u5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0417");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-0412");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwireshark-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwireshark-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwireshark11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwiretap-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwiretap8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwscodecs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwsutil-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwsutil9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-qt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'release': '10.0', 'prefix': 'libwireshark-data', 'reference': '2.6.20-0+deb10u5'},
    {'release': '10.0', 'prefix': 'libwireshark-dev', 'reference': '2.6.20-0+deb10u5'},
    {'release': '10.0', 'prefix': 'libwireshark11', 'reference': '2.6.20-0+deb10u5'},
    {'release': '10.0', 'prefix': 'libwiretap-dev', 'reference': '2.6.20-0+deb10u5'},
    {'release': '10.0', 'prefix': 'libwiretap8', 'reference': '2.6.20-0+deb10u5'},
    {'release': '10.0', 'prefix': 'libwscodecs2', 'reference': '2.6.20-0+deb10u5'},
    {'release': '10.0', 'prefix': 'libwsutil-dev', 'reference': '2.6.20-0+deb10u5'},
    {'release': '10.0', 'prefix': 'libwsutil9', 'reference': '2.6.20-0+deb10u5'},
    {'release': '10.0', 'prefix': 'tshark', 'reference': '2.6.20-0+deb10u5'},
    {'release': '10.0', 'prefix': 'wireshark', 'reference': '2.6.20-0+deb10u5'},
    {'release': '10.0', 'prefix': 'wireshark-common', 'reference': '2.6.20-0+deb10u5'},
    {'release': '10.0', 'prefix': 'wireshark-dev', 'reference': '2.6.20-0+deb10u5'},
    {'release': '10.0', 'prefix': 'wireshark-doc', 'reference': '2.6.20-0+deb10u5'},
    {'release': '10.0', 'prefix': 'wireshark-gtk', 'reference': '2.6.20-0+deb10u5'},
    {'release': '10.0', 'prefix': 'wireshark-qt', 'reference': '2.6.20-0+deb10u5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libwireshark-data / libwireshark-dev / libwireshark11 / libwiretap-dev / etc');
}
