#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5354. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(171628);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/18");

  script_cve_id(
    "CVE-2020-3299",
    "CVE-2020-3315",
    "CVE-2021-1223",
    "CVE-2021-1224",
    "CVE-2021-1236",
    "CVE-2021-1494",
    "CVE-2021-1495",
    "CVE-2021-34749",
    "CVE-2021-40114"
  );
  script_xref(name:"IAVA", value:"2021-A-0393");
  script_xref(name:"IAVA", value:"2020-A-0497");
  script_xref(name:"IAVA", value:"2021-A-0027");
  script_xref(name:"IAVA", value:"2021-A-0249");

  script_name(english:"Debian DSA-5354-1 : snort - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5354 advisory.

  - Multiple Cisco products are affected by a vulnerability in the Snort detection engine that could allow an
    unauthenticated, remote attacker to bypass a configured File Policy for HTTP. The vulnerability is due to
    incorrect detection of modified HTTP packets used in chunked responses. An attacker could exploit this
    vulnerability by sending crafted HTTP packets through an affected device. A successful exploit could allow
    the attacker to bypass a configured File Policy for HTTP packets and deliver a malicious payload.
    (CVE-2020-3299)

  - Multiple Cisco products are affected by a vulnerability in the Snort detection engine that could allow an
    unauthenticated, remote attacker to bypass the configured file policies on an affected system. The
    vulnerability is due to errors in how the Snort detection engine handles specific HTTP responses. An
    attacker could exploit this vulnerability by sending crafted HTTP packets that would flow through an
    affected system. A successful exploit could allow the attacker to bypass the configured file policies and
    deliver a malicious payload to the protected network. (CVE-2020-3315)

  - Multiple Cisco products are affected by a vulnerability in the Snort detection engine that could allow an
    unauthenticated, remote attacker to bypass a configured file policy for HTTP. The vulnerability is due to
    incorrect handling of an HTTP range header. An attacker could exploit this vulnerability by sending
    crafted HTTP packets through an affected device. A successful exploit could allow the attacker to bypass
    configured file policy for HTTP packets and deliver a malicious payload. (CVE-2021-1223)

  - Multiple Cisco products are affected by a vulnerability with TCP Fast Open (TFO) when used in conjunction
    with the Snort detection engine that could allow an unauthenticated, remote attacker to bypass a
    configured file policy for HTTP. The vulnerability is due to incorrect detection of the HTTP payload if it
    is contained at least partially within the TFO connection handshake. An attacker could exploit this
    vulnerability by sending crafted TFO packets with an HTTP payload through an affected device. A successful
    exploit could allow the attacker to bypass configured file policy for HTTP packets and deliver a malicious
    payload. (CVE-2021-1224)

  - Multiple Cisco products are affected by a vulnerability in the Snort application detection engine that
    could allow an unauthenticated, remote attacker to bypass the configured policies on an affected system.
    The vulnerability is due to a flaw in the detection algorithm. An attacker could exploit this
    vulnerability by sending crafted packets that would flow through an affected system. A successful exploit
    could allow the attacker to bypass the configured policies and deliver a malicious payload to the
    protected network. (CVE-2021-1236)

  - Multiple Cisco products are affected by a vulnerability in the Snort detection engine that could allow an
    unauthenticated, remote attacker to bypass a configured file policy for HTTP. The vulnerability is due to
    incorrect handling of specific HTTP header parameters. An attacker could exploit this vulnerability by
    sending crafted HTTP packets through an affected device. A successful exploit could allow the attacker to
    bypass a configured file policy for HTTP packets and deliver a malicious payload. (CVE-2021-1495)

  - A vulnerability in Server Name Identification (SNI) request filtering of Cisco Web Security Appliance
    (WSA), Cisco Firepower Threat Defense (FTD), and the Snort detection engine could allow an
    unauthenticated, remote attacker to bypass filtering technology on an affected device and exfiltrate data
    from a compromised host. This vulnerability is due to inadequate filtering of the SSL handshake. An
    attacker could exploit this vulnerability by using data from the SSL client hello packet to communicate
    with an external server. A successful exploit could allow the attacker to execute a command-and-control
    attack on a compromised host and perform additional data exfiltration attacks. (CVE-2021-34749)

  - Multiple Cisco products are affected by a vulnerability in the way the Snort detection engine processes
    ICMP traffic that could allow an unauthenticated, remote attacker to cause a denial of service (DoS)
    condition on an affected device. The vulnerability is due to improper memory resource management while the
    Snort detection engine is processing ICMP packets. An attacker could exploit this vulnerability by sending
    a series of ICMP packets through an affected device. A successful exploit could allow the attacker to
    exhaust resources on the affected device, causing the device to reload. (CVE-2021-40114)

  - Multiple Ciscoproducts are affected by vulnerabilities in the Snort detection engine that could allow an
    unauthenticated, remote attacker to bypass a configured file policy for HTTP. (CVE-2021-1494)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1021276");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/snort");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5354");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-3299");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-3315");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-1223");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-1224");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-1236");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-1494");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-1495");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-34749");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-40114");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/snort");
  script_set_attribute(attribute:"solution", value:
"Upgrade the snort packages.

For the stable distribution (bullseye), these problems have been fixed in version 2.9.20-0+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34749");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:snort");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:snort-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:snort-common-libraries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:snort-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:snort-rules-default");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'snort', 'reference': '2.9.20-0+deb11u1'},
    {'release': '11.0', 'prefix': 'snort-common', 'reference': '2.9.20-0+deb11u1'},
    {'release': '11.0', 'prefix': 'snort-common-libraries', 'reference': '2.9.20-0+deb11u1'},
    {'release': '11.0', 'prefix': 'snort-doc', 'reference': '2.9.20-0+deb11u1'},
    {'release': '11.0', 'prefix': 'snort-rules-default', 'reference': '2.9.20-0+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'snort / snort-common / snort-common-libraries / snort-doc / etc');
}
