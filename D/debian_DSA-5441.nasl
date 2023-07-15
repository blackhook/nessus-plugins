#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5441. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(177736);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/29");

  script_cve_id("CVE-2022-30256", "CVE-2023-31137");

  script_name(english:"Debian DSA-5441-1 : maradns - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5441 advisory.

  - An issue was discovered in MaraDNS Deadwood through 3.5.0021 that allows variant V1 of unintended domain
    name resolution. A revoked domain name can still be resolvable for a long time, including expired domains
    and taken-down malicious domains. The effects of an exploit would be widespread and highly impactful,
    because the exploitation conforms to de facto DNS specifications and operational practices, and overcomes
    current mitigation patches for Ghost domain names. (CVE-2022-30256)

  - MaraDNS is open-source software that implements the Domain Name System (DNS). In version 3.5.0024 and
    prior, a remotely exploitable integer underflow vulnerability in the DNS packet decompression function
    allows an attacker to cause a Denial of Service by triggering an abnormal program termination. The
    vulnerability exists in the `decomp_get_rddata` function within the `Decompress.c` file. When handling a
    DNS packet with an Answer RR of qtype 16 (TXT record) and any qclass, if the `rdlength` is smaller than
    `rdata`, the result of the line `Decompress.c:886` is a negative number `len = rdlength - total;`. This
    value is then passed to the `decomp_append_bytes` function without proper validation, causing the program
    to attempt to allocate a massive chunk of memory that is impossible to allocate. Consequently, the program
    exits with an error code of 64, causing a Denial of Service. One proposed fix for this vulnerability is to
    patch `Decompress.c:887` by breaking `if(len <= 0)`, which has been incorporated in version 3.5.0036 via
    commit bab062bde40b2ae8a91eecd522e84d8b993bab58. (CVE-2023-31137)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1033252");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/maradns");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5441");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-30256");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-31137");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/maradns");
  script_set_attribute(attribute:"solution", value:
"Upgrade the maradns packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-30256");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:duende");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:maradns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:maradns-deadwood");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:maradns-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:maradns-zoneserver");
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
    {'release': '11.0', 'prefix': 'duende', 'reference': '2.0.13-1.4+deb11u1'},
    {'release': '11.0', 'prefix': 'maradns', 'reference': '2.0.13-1.4+deb11u1'},
    {'release': '11.0', 'prefix': 'maradns-deadwood', 'reference': '2.0.13-1.4+deb11u1'},
    {'release': '11.0', 'prefix': 'maradns-docs', 'reference': '2.0.13-1.4+deb11u1'},
    {'release': '11.0', 'prefix': 'maradns-zoneserver', 'reference': '2.0.13-1.4+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'duende / maradns / maradns-deadwood / maradns-docs / etc');
}
