#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5410. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(176334);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_cve_id(
    "CVE-2022-31001",
    "CVE-2022-31002",
    "CVE-2022-31003",
    "CVE-2022-47516",
    "CVE-2023-22741"
  );

  script_name(english:"Debian DSA-5410-1 : sofia-sip - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5410 advisory.

  - Sofia-SIP is an open-source Session Initiation Protocol (SIP) User-Agent library. Prior to version 1.13.8,
    an attacker can send a message with evil sdp to FreeSWITCH, which may cause crash. This type of crash may
    be caused by `#define MATCH(s, m) (strncmp(s, m, n = sizeof(m) - 1) == 0)`, which will make `n` bigger and
    trigger out-of-bound access when `IS_NON_WS(s[n])`. Version 1.13.8 contains a patch for this issue.
    (CVE-2022-31001)

  - Sofia-SIP is an open-source Session Initiation Protocol (SIP) User-Agent library. Prior to version 1.13.8,
    an attacker can send a message with evil sdp to FreeSWITCH, which may cause a crash. This type of crash
    may be caused by a URL ending with `%`. Version 1.13.8 contains a patch for this issue. (CVE-2022-31002)

  - Sofia-SIP is an open-source Session Initiation Protocol (SIP) User-Agent library. Prior to version 1.13.8,
    when parsing each line of a sdp message, `rest = record + 2` will access the memory behind `\0` and cause
    an out-of-bounds write. An attacker can send a message with evil sdp to FreeSWITCH, causing a crash or
    more serious consequence, such as remote code execution. Version 1.13.8 contains a patch for this issue.
    (CVE-2022-31003)

  - An issue was discovered in the libsofia-sip fork in drachtio-server before 0.8.20. It allows remote
    attackers to cause a denial of service (daemon crash) via a crafted UDP message that leads to a failure of
    the libsofia-sip-ua/tport/tport.c self assertion. (CVE-2022-47516)

  - Sofia-SIP is an open-source SIP User-Agent library, compliant with the IETF RFC3261 specification. In
    affected versions Sofia-SIP **lacks both message length and attributes length checks** when it handles
    STUN packets, leading to controllable heap-over-flow. For example, in stun_parse_attribute(), after we get
    the attribute's type and length value, the length will be used directly to copy from the heap, regardless
    of the message's left size. Since network users control the overflowed length, and the data is written to
    heap chunks later, attackers may achieve remote code execution by heap grooming or other exploitation
    methods. The bug was introduced 16 years ago in sofia-sip 1.12.4 (plus some patches through 12/21/2006) to
    in tree libs with git-svn-id: http://svn.freeswitch.org/svn/freeswitch/trunk@3774
    d0543943-73ff-0310-b7d9-9358b9ac24b2. Users are advised to upgrade. There are no known workarounds for
    this vulnerability. (CVE-2023-22741)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/sofia-sip");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5410");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-31001");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-31002");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-31003");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-47516");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-22741");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/sofia-sip");
  script_set_attribute(attribute:"solution", value:
"Upgrade the sofia-sip packages.

For the stable distribution (bullseye), these problems have been fixed in version 1.12.11+20110422.1-2.1+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31003");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-22741");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsofia-sip-ua-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsofia-sip-ua-glib-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsofia-sip-ua-glib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsofia-sip-ua0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sofia-sip-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sofia-sip-doc");
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
    {'release': '11.0', 'prefix': 'libsofia-sip-ua-dev', 'reference': '1.12.11+20110422.1-2.1+deb11u1'},
    {'release': '11.0', 'prefix': 'libsofia-sip-ua-glib-dev', 'reference': '1.12.11+20110422.1-2.1+deb11u1'},
    {'release': '11.0', 'prefix': 'libsofia-sip-ua-glib3', 'reference': '1.12.11+20110422.1-2.1+deb11u1'},
    {'release': '11.0', 'prefix': 'libsofia-sip-ua0', 'reference': '1.12.11+20110422.1-2.1+deb11u1'},
    {'release': '11.0', 'prefix': 'sofia-sip-bin', 'reference': '1.12.11+20110422.1-2.1+deb11u1'},
    {'release': '11.0', 'prefix': 'sofia-sip-doc', 'reference': '1.12.11+20110422.1-2.1+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libsofia-sip-ua-dev / libsofia-sip-ua-glib-dev / libsofia-sip-ua-glib3 / etc');
}
