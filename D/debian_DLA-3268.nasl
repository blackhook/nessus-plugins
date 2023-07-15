#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3268. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(170079);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/16");

  script_cve_id(
    "CVE-2021-37136",
    "CVE-2021-37137",
    "CVE-2021-43797",
    "CVE-2022-41881",
    "CVE-2022-41915"
  );

  script_name(english:"Debian DLA-3268-1 : netty - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dla-3268 advisory.

  - The Bzip2 decompression decoder function doesn't allow setting size restrictions on the decompressed
    output data (which affects the allocation size used during decompression). All users of Bzip2Decoder are
    affected. The malicious input can trigger an OOME and so a DoS attack (CVE-2021-37136)

  - The Snappy frame decoder function doesn't restrict the chunk length which may lead to excessive memory
    usage. Beside this it also may buffer reserved skippable chunks until the whole chunk was received which
    may lead to excessive memory usage as well. This vulnerability can be triggered by supplying malicious
    input that decompresses to a very big size (via a network stream or a file) or by sending a huge skippable
    chunk. (CVE-2021-37137)

  - Netty is an asynchronous event-driven network application framework for rapid development of maintainable
    high performance protocol servers & clients. Netty prior to version 4.1.71.Final skips control chars when
    they are present at the beginning / end of the header name. It should instead fail fast as these are not
    allowed by the spec and could lead to HTTP request smuggling. Failing to do the validation might cause
    netty to sanitize header names before it forward these to another remote system when used as proxy. This
    remote system can't see the invalid usage anymore, and therefore does not do the validation itself. Users
    should upgrade to version 4.1.71.Final. (CVE-2021-43797)

  - Netty project is an event-driven asynchronous network application framework. In versions prior to
    4.1.86.Final, a StackOverflowError can be raised when parsing a malformed crafted message due to an
    infinite recursion. This issue is patched in version 4.1.86.Final. There is no workaround, except using a
    custom HaProxyMessageDecoder. (CVE-2022-41881)

  - Netty project is an event-driven asynchronous network application framework. Starting in version
    4.1.83.Final and prior to 4.1.86.Final, when calling `DefaultHttpHeadesr.set` with an _iterator_ of
    values, header value validation was not performed, allowing malicious header values in the iterator to
    perform HTTP Response Splitting. This issue has been patched in version 4.1.86.Final. Integrators can work
    around the issue by changing the `DefaultHttpHeaders.set(CharSequence, Iterator<?>)` call, into a
    `remove()` call, and call `add()` in a loop over the iterator of values. (CVE-2022-41915)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1027180");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/netty");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3268");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37136");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37137");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43797");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41881");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41915");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/netty");
  script_set_attribute(attribute:"solution", value:
"Upgrade the netty packages.

For Debian 10 buster, these problems have been fixed in version 1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43797");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-41915");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnetty-java");
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
    {'release': '10.0', 'prefix': 'libnetty-java', 'reference': '1:4.1.33-1+deb10u3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libnetty-java');
}
