#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6049-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174932);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id(
    "CVE-2020-11612",
    "CVE-2021-21290",
    "CVE-2021-21295",
    "CVE-2021-21409",
    "CVE-2021-37136",
    "CVE-2021-37137",
    "CVE-2021-43797",
    "CVE-2022-41881",
    "CVE-2022-41915"
  );
  script_xref(name:"USN", value:"6049-1");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 ESM / 20.04 ESM / 22.04 LTS / 22.10 : Netty vulnerabilities (USN-6049-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 ESM / 20.04 ESM / 22.04 LTS host has a package installed that is affected by
multiple vulnerabilities as referenced in the USN-6049-1 advisory.

  - The ZlibDecoders in Netty 4.1.x before 4.1.46 allow for unbounded memory allocation while decoding a
    ZlibEncoded byte stream. An attacker could send a large ZlibEncoded byte stream to the Netty server,
    forcing the server to allocate all of its free memory to a single decoder. (CVE-2020-11612)

  - Netty is an open-source, asynchronous event-driven network application framework for rapid development of
    maintainable high performance protocol servers & clients. In Netty before version 4.1.59.Final there is a
    vulnerability on Unix-like systems involving an insecure temp file. When netty's multipart decoders are
    used local information disclosure can occur via the local system temporary directory if temporary storing
    uploads on the disk is enabled. On unix-like systems, the temporary directory is shared between all user.
    As such, writing to this directory using APIs that do not explicitly set the file/directory permissions
    can lead to information disclosure. Of note, this does not impact modern MacOS Operating Systems. The
    method File.createTempFile on unix-like systems creates a random file, but, by default will create this
    file with the permissions -rw-r--r--. Thus, if sensitive information is written to this file, other
    local users can read this information. This is the case in netty's AbstractDiskHttpData is vulnerable.
    This has been fixed in version 4.1.59.Final. As a workaround, one may specify your own java.io.tmpdir
    when you start the JVM or use DefaultHttpDataFactory.setBaseDir(...) to set the directory to something
    that is only readable by the current user. (CVE-2021-21290)

  - Netty is an open-source, asynchronous event-driven network application framework for rapid development of
    maintainable high performance protocol servers & clients. In Netty (io.netty:netty-codec-http2) before
    version 4.1.60.Final there is a vulnerability that enables request smuggling. If a Content-Length header
    is present in the original HTTP/2 request, the field is not validated by `Http2MultiplexHandler` as it is
    propagated up. This is fine as long as the request is not proxied through as HTTP/1.1. If the request
    comes in as an HTTP/2 stream, gets converted into the HTTP/1.1 domain objects (`HttpRequest`,
    `HttpContent`, etc.) via `Http2StreamFrameToHttpObjectCodec `and then sent up to the child channel's
    pipeline and proxied through a remote peer as HTTP/1.1 this may result in request smuggling. In a proxy
    case, users may assume the content-length is validated somehow, which is not the case. If the request is
    forwarded to a backend channel that is a HTTP/1.1 connection, the Content-Length now has meaning and needs
    to be checked. An attacker can smuggle requests inside the body as it gets downgraded from HTTP/2 to
    HTTP/1.1. For an example attack refer to the linked GitHub Advisory. Users are only affected if all of
    this is true: `HTTP2MultiplexCodec` or `Http2FrameCodec` is used, `Http2StreamFrameToHttpObjectCodec` is
    used to convert to HTTP/1.1 objects, and these HTTP/1.1 objects are forwarded to another remote peer. This
    has been patched in 4.1.60.Final As a workaround, the user can do the validation by themselves by
    implementing a custom `ChannelInboundHandler` that is put in the `ChannelPipeline` behind
    `Http2StreamFrameToHttpObjectCodec`. (CVE-2021-21295)

  - Netty is an open-source, asynchronous event-driven network application framework for rapid development of
    maintainable high performance protocol servers & clients. In Netty (io.netty:netty-codec-http2) before
    version 4.1.61.Final there is a vulnerability that enables request smuggling. The content-length header is
    not correctly validated if the request only uses a single Http2HeaderFrame with the endStream set to to
    true. This could lead to request smuggling if the request is proxied to a remote peer and translated to
    HTTP/1.1. This is a followup of GHSA-wm47-8v5p-wjpj/CVE-2021-21295 which did miss to fix this one case.
    This was fixed as part of 4.1.61.Final. (CVE-2021-21409)

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
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6049-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected libnetty-java package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43797");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-41915");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnetty-java");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023 Canonical, Inc. / NASL script (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! preg(pattern:"^(16\.04|18\.04|20\.04|22\.04|22\.10)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'libnetty-java', 'pkgver': '1:4.0.34-1ubuntu0.1~esm1'},
    {'osver': '18.04', 'pkgname': 'libnetty-java', 'pkgver': '1:4.1.7-4ubuntu0.1+esm2'},
    {'osver': '20.04', 'pkgname': 'libnetty-java', 'pkgver': '1:4.1.45-1ubuntu0.1~esm1'},
    {'osver': '22.04', 'pkgname': 'libnetty-java', 'pkgver': '1:4.1.48-4+deb11u1build0.22.04.1'},
    {'osver': '22.10', 'pkgname': 'libnetty-java', 'pkgver': '1:4.1.48-5ubuntu0.1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libnetty-java');
}
