#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3380. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(173776);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/19");

  script_cve_id(
    "CVE-2020-12362",
    "CVE-2020-12363",
    "CVE-2020-12364",
    "CVE-2020-24586",
    "CVE-2020-24587",
    "CVE-2020-24588",
    "CVE-2021-23168",
    "CVE-2021-23223",
    "CVE-2021-37409",
    "CVE-2021-44545",
    "CVE-2022-21181"
  );

  script_name(english:"Debian DLA-3380-1 : firmware-nonfree - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dla-3380 advisory.

  - Integer overflow in the firmware for some Intel(R) Graphics Drivers for Windows * before version
    26.20.100.7212 and before Linux kernel version 5.5 may allow a privileged user to potentially enable an
    escalation of privilege via local access. (CVE-2020-12362)

  - Improper input validation in some Intel(R) Graphics Drivers for Windows* before version 26.20.100.7212 and
    before Linux kernel version 5.5 may allow a privileged user to potentially enable a denial of service via
    local access. (CVE-2020-12363)

  - Null pointer reference in some Intel(R) Graphics Drivers for Windows* before version 26.20.100.7212 and
    before version Linux kernel version 5.5 may allow a privileged user to potentially enable a denial of
    service via local access. (CVE-2020-12364)

  - The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and WPA3) and Wired Equivalent
    Privacy (WEP) doesn't require that received fragments be cleared from memory after (re)connecting to a
    network. Under the right circumstances, when another device sends fragmented frames encrypted using WEP,
    CCMP, or GCMP, this can be abused to inject arbitrary network packets and/or exfiltrate user data.
    (CVE-2020-24586)

  - The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and WPA3) and Wired Equivalent
    Privacy (WEP) doesn't require that all fragments of a frame are encrypted under the same key. An adversary
    can abuse this to decrypt selected fragments when another device sends fragmented frames and the WEP,
    CCMP, or GCMP encryption key is periodically renewed. (CVE-2020-24587)

  - The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and WPA3) and Wired Equivalent
    Privacy (WEP) doesn't require that the A-MSDU flag in the plaintext QoS header field is authenticated.
    Against devices that support receiving non-SSP A-MSDU frames (which is mandatory as part of 802.11n), an
    adversary can abuse this to inject arbitrary network packets. (CVE-2020-24588)

  - Out of bounds read for some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi products may allow an
    unauthenticated user to potentially enable denial of service via adjacent access. (CVE-2021-23168)

  - Improper initialization for some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi products may allow a
    privileged user to potentially enable escalation of privilege via local access. (CVE-2021-23223)

  - Improper access control for some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi products may allow a
    privileged user to potentially enable escalation of privilege via local access. (CVE-2021-37409)

  - Improper input validation for some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi products may allow an
    unauthenticated user to potentially enable denial of service via adjacent access. (CVE-2021-44545)

  - Improper input validation for some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi products may allow a
    privileged user to potentially enable escalation of privilege via local access. (CVE-2022-21181)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=844056");
  # https://security-tracker.debian.org/tracker/source-package/firmware-nonfree
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42c4e444");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3380");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-12362");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-12363");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-12364");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-24586");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-24587");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-24588");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-23168");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-23223");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37409");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-44545");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21181");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/firmware-nonfree");
  script_set_attribute(attribute:"solution", value:
"Upgrade the firmware-nonfree packages.

For Debian 10 buster, these problems have been fixed in version 20190114+really20220913-0+deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12362");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-21181");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-adi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-amd-graphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-atheros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-bnx2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-bnx2x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-brcm80211");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-cavium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-intel-sound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-intelwimax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-ipw2x00");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-ivtv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-iwlwifi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-libertas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-linux-nonfree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-misc-nonfree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-myricom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-netronome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-netxen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-qcom-media");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-qlogic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-ralink");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-realtek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-samsung");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-siano");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-ti-connectivity");
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
    {'release': '10.0', 'prefix': 'firmware-adi', 'reference': '20190114+really20220913-0+deb10u1'},
    {'release': '10.0', 'prefix': 'firmware-amd-graphics', 'reference': '20190114+really20220913-0+deb10u1'},
    {'release': '10.0', 'prefix': 'firmware-atheros', 'reference': '20190114+really20220913-0+deb10u1'},
    {'release': '10.0', 'prefix': 'firmware-bnx2', 'reference': '20190114+really20220913-0+deb10u1'},
    {'release': '10.0', 'prefix': 'firmware-bnx2x', 'reference': '20190114+really20220913-0+deb10u1'},
    {'release': '10.0', 'prefix': 'firmware-brcm80211', 'reference': '20190114+really20220913-0+deb10u1'},
    {'release': '10.0', 'prefix': 'firmware-cavium', 'reference': '20190114+really20220913-0+deb10u1'},
    {'release': '10.0', 'prefix': 'firmware-intel-sound', 'reference': '20190114+really20220913-0+deb10u1'},
    {'release': '10.0', 'prefix': 'firmware-intelwimax', 'reference': '20190114+really20220913-0+deb10u1'},
    {'release': '10.0', 'prefix': 'firmware-ipw2x00', 'reference': '20190114+really20220913-0+deb10u1'},
    {'release': '10.0', 'prefix': 'firmware-ivtv', 'reference': '20190114+really20220913-0+deb10u1'},
    {'release': '10.0', 'prefix': 'firmware-iwlwifi', 'reference': '20190114+really20220913-0+deb10u1'},
    {'release': '10.0', 'prefix': 'firmware-libertas', 'reference': '20190114+really20220913-0+deb10u1'},
    {'release': '10.0', 'prefix': 'firmware-linux', 'reference': '20190114+really20220913-0+deb10u1'},
    {'release': '10.0', 'prefix': 'firmware-linux-nonfree', 'reference': '20190114+really20220913-0+deb10u1'},
    {'release': '10.0', 'prefix': 'firmware-misc-nonfree', 'reference': '20190114+really20220913-0+deb10u1'},
    {'release': '10.0', 'prefix': 'firmware-myricom', 'reference': '20190114+really20220913-0+deb10u1'},
    {'release': '10.0', 'prefix': 'firmware-netronome', 'reference': '20190114+really20220913-0+deb10u1'},
    {'release': '10.0', 'prefix': 'firmware-netxen', 'reference': '20190114+really20220913-0+deb10u1'},
    {'release': '10.0', 'prefix': 'firmware-qcom-media', 'reference': '20190114+really20220913-0+deb10u1'},
    {'release': '10.0', 'prefix': 'firmware-qlogic', 'reference': '20190114+really20220913-0+deb10u1'},
    {'release': '10.0', 'prefix': 'firmware-ralink', 'reference': '20190114+really20220913-0+deb10u1'},
    {'release': '10.0', 'prefix': 'firmware-realtek', 'reference': '20190114+really20220913-0+deb10u1'},
    {'release': '10.0', 'prefix': 'firmware-samsung', 'reference': '20190114+really20220913-0+deb10u1'},
    {'release': '10.0', 'prefix': 'firmware-siano', 'reference': '20190114+really20220913-0+deb10u1'},
    {'release': '10.0', 'prefix': 'firmware-ti-connectivity', 'reference': '20190114+really20220913-0+deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'firmware-adi / firmware-amd-graphics / firmware-atheros / etc');
}
