#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5429. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(177382);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/19");

  script_cve_id(
    "CVE-2023-0666",
    "CVE-2023-0668",
    "CVE-2023-1161",
    "CVE-2023-1992",
    "CVE-2023-1993",
    "CVE-2023-1994",
    "CVE-2023-2854",
    "CVE-2023-2855",
    "CVE-2023-2856",
    "CVE-2023-2857",
    "CVE-2023-2858",
    "CVE-2023-2879",
    "CVE-2023-2952"
  );
  script_xref(name:"IAVB", value:"2023-B-0024-S");
  script_xref(name:"IAVB", value:"2023-B-0036");

  script_name(english:"Debian DSA-5429-1 : wireshark - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5429 advisory.

  - Due to failure in validating the length provided by an attacker-crafted RTPS packet, Wireshark version
    4.0.5 and prior, by default, is susceptible to a heap-based buffer overflow, and possibly code execution
    in the context of the process running Wireshark. (CVE-2023-0666)

  - Due to failure in validating the length provided by an attacker-crafted IEEE-C37.118 packet, Wireshark
    version 4.0.5 and prior, by default, is susceptible to a heap-based buffer overflow, and possibly code
    execution in the context of the process running Wireshark. (CVE-2023-0668)

  - ISO 15765 and ISO 10681 dissector crash in Wireshark 4.0.0 to 4.0.3 and 3.6.0 to 3.6.11 allows denial of
    service via packet injection or crafted capture file (CVE-2023-1161)

  - RPCoRDMA dissector crash in Wireshark 4.0.0 to 4.0.4 and 3.6.0 to 3.6.12 allows denial of service via
    packet injection or crafted capture file (CVE-2023-1992)

  - LISP dissector large loop in Wireshark 4.0.0 to 4.0.4 and 3.6.0 to 3.6.12 allows denial of service via
    packet injection or crafted capture file (CVE-2023-1993)

  - GQUIC dissector crash in Wireshark 4.0.0 to 4.0.4 and 3.6.0 to 3.6.12 allows denial of service via packet
    injection or crafted capture file (CVE-2023-1994)

  - BLF file parser crash in Wireshark 4.0.0 to 4.0.5 and 3.6.0 to 3.6.13 allows denial of service via crafted
    capture file (CVE-2023-2854, CVE-2023-2857)

  - Candump log parser crash in Wireshark 4.0.0 to 4.0.5 and 3.6.0 to 3.6.13 allows denial of service via
    crafted capture file (CVE-2023-2855)

  - VMS TCPIPtrace file parser crash in Wireshark 4.0.0 to 4.0.5 and 3.6.0 to 3.6.13 allows denial of service
    via crafted capture file (CVE-2023-2856)

  - NetScaler file parser crash in Wireshark 4.0.0 to 4.0.5 and 3.6.0 to 3.6.13 allows denial of service via
    crafted capture file (CVE-2023-2858)

  - GDSDB infinite loop in Wireshark 4.0.0 to 4.0.5 and 3.6.0 to 3.6.13 allows denial of service via packet
    injection or crafted capture file (CVE-2023-2879)

  - XRA dissector infinite loop in Wireshark 4.0.0 to 4.0.5 and 3.6.0 to 3.6.13 allows denial of service via
    packet injection or crafted capture file (CVE-2023-2952)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/wireshark");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5429");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0666");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0668");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1161");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1992");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1993");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1994");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2854");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2855");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2856");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2857");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2858");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2879");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2952");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/wireshark");
  script_set_attribute(attribute:"solution", value:
"Upgrade the wireshark packages.

For the stable distribution (bookworm), these problems have been fixed in version 4.0.6-1~deb12u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1161");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwireshark-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwireshark-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwireshark16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwiretap-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwiretap13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwsutil-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwsutil14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-qt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
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
if (! preg(pattern:"^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '12.0', 'prefix': 'libwireshark-data', 'reference': '4.0.6-1~deb12u1'},
    {'release': '12.0', 'prefix': 'libwireshark-dev', 'reference': '4.0.6-1~deb12u1'},
    {'release': '12.0', 'prefix': 'libwireshark16', 'reference': '4.0.6-1~deb12u1'},
    {'release': '12.0', 'prefix': 'libwiretap-dev', 'reference': '4.0.6-1~deb12u1'},
    {'release': '12.0', 'prefix': 'libwiretap13', 'reference': '4.0.6-1~deb12u1'},
    {'release': '12.0', 'prefix': 'libwsutil-dev', 'reference': '4.0.6-1~deb12u1'},
    {'release': '12.0', 'prefix': 'libwsutil14', 'reference': '4.0.6-1~deb12u1'},
    {'release': '12.0', 'prefix': 'tshark', 'reference': '4.0.6-1~deb12u1'},
    {'release': '12.0', 'prefix': 'wireshark', 'reference': '4.0.6-1~deb12u1'},
    {'release': '12.0', 'prefix': 'wireshark-common', 'reference': '4.0.6-1~deb12u1'},
    {'release': '12.0', 'prefix': 'wireshark-dev', 'reference': '4.0.6-1~deb12u1'},
    {'release': '12.0', 'prefix': 'wireshark-doc', 'reference': '4.0.6-1~deb12u1'},
    {'release': '12.0', 'prefix': 'wireshark-gtk', 'reference': '4.0.6-1~deb12u1'},
    {'release': '12.0', 'prefix': 'wireshark-qt', 'reference': '4.0.6-1~deb12u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libwireshark-data / libwireshark-dev / libwireshark16 / libwiretap-dev / etc');
}
