#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3034. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(161700);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/31");

  script_cve_id("CVE-2018-20102", "CVE-2018-20103", "CVE-2019-18277");

  script_name(english:"Debian DLA-3034-1 : haproxy - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3034 advisory.

  - An out-of-bounds read in dns_validate_dns_response in dns.c was discovered in HAProxy through 1.8.14. Due
    to a missing check when validating DNS responses, remote attackers might be able read the 16 bytes
    corresponding to an AAAA record from the non-initialized part of the buffer, possibly accessing anything
    that was left on the stack, or even past the end of the 8193-byte buffer, depending on the value of
    accepted_payload_size. (CVE-2018-20102)

  - An issue was discovered in dns.c in HAProxy through 1.8.14. In the case of a compressed pointer, a crafted
    packet can trigger infinite recursion by making the pointer point to itself, or create a long chain of
    valid pointers resulting in stack exhaustion. (CVE-2018-20103)

  - A flaw was found in HAProxy before 2.0.6. In legacy mode, messages featuring a transfer-encoding header
    missing the chunked value were not being correctly rejected. The impact was limited but if combined with
    the http-reuse always setting, it could be used to help construct an HTTP request smuggling attack
    against a vulnerable component employing a lenient parser that would ignore the content-length header as
    soon as it saw a transfer-encoding one (even if not entirely valid according to the specification).
    (CVE-2019-18277)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=916308");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/haproxy");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3034");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-20102");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-20103");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-18277");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/haproxy");
  script_set_attribute(attribute:"solution", value:
"Upgrade the haproxy packages.

For Debian 9 stretch, these problems have been fixed in version 1.7.5-2+deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-20102");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-18277");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:haproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:haproxy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-haproxy");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
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
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'haproxy', 'reference': '1.7.5-2+deb9u1'},
    {'release': '9.0', 'prefix': 'haproxy-doc', 'reference': '1.7.5-2+deb9u1'},
    {'release': '9.0', 'prefix': 'vim-haproxy', 'reference': '1.7.5-2+deb9u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'haproxy / haproxy-doc / vim-haproxy');
}
