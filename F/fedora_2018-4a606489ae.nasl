#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-4a606489ae.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120396);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_xref(name:"FEDORA", value:"2018-4a606489ae");

  script_name(english:"Fedora 28 : php-zendframework-zend-diactoros (2018-4a606489ae)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"## 1.8.4 - 2018-08-01

### Added

  - Nothing.

### Changed

  - This release modifies how `ServerRequestFactory`
    marshals the request URI. In prior releases, we would
    attempt to inspect the `X-Rewrite-Url` and
    `X-Original-Url` headers, using their values, if
    present. These headers are issued by the ISAPI_Rewrite
    module for IIS (developed by HeliconTech). However, we
    have no way of guaranteeing that the module is what
    issued the headers, making it an unreliable source for
    discovering the URI. As such, we have removed this
    feature in this release of Diactoros.

    If you are developing a middleware application, you can
    mimic the functionality via middleware as follows :

``` use Psr\Http\Message\ResponseInterface; use
Psr\Http\Message\ServerRequestInterface; use
Psr\Http\Server\RequestHandlerInterface; use Zend\Diactoros\Uri;

public function process(ServerRequestInterface $request,
RequestHandlerInterface $handler) : ResponseInterface { $requestUri =
null;

$httpXRewriteUrl = $request->getHeaderLine('X-Rewrite-Url'); if
($httpXRewriteUrl !== null) { $requestUri = $httpXRewriteUrl; }

$httpXOriginalUrl =
$request->getHeaderLine('X-Original-Url'); if
($httpXOriginalUrl !== null) { $requestUri =
$httpXOriginalUrl; }

if ($requestUri !== null) { $request = $request->withUri(new
Uri($requestUri)); }

return $handler->handle($request); } ```

If you use middleware such as the above, make sure you also
instruct your web server to strip any incoming headers of
the same name so that you can guarantee they are issued by
the ISAPI_Rewrite module.

### Deprecated

  - Nothing.

### Removed

  - Nothing.

### Fixed

  - Nothing.

## 1.8.3 - 2018-07-24

### Added

  - Nothing.

### Changed

  - Nothing.

### Deprecated

  - Nothing.

### Removed

  - Nothing.

### Fixed

  -
    [#321](https://github.com/zendframework/zend-diactoros/p
    ull/321) updates the logic in `Uri::withPort()` to
    ensure that it checks that the value provided is either
    an integer or a string integer, as only those values may
    be cast to integer without data loss.

  -
    [#320](https://github.com/zendframework/zend-diactoros/p
    ull/320) adds checking within `Response` to ensure that
    the provided reason phrase is a string; an
    `InvalidArgumentException` is now raised if it is not.
    This change ensures the class adheres strictly to the
    PSR-7 specification.

  -
    [#319](https://github.com/zendframework/zend-diactoros/p
    ull/319) provides a fix to `Zend\Diactoros\Response`
    that ensures that the status code returned is _always_
    an integer (and never a string containing an integer),
    thus ensuring it strictly adheres to the PSR-7
    specification.

## 1.8.2 - 2018-07-19

### Added

  - Nothing.

### Changed

  - Nothing.

### Deprecated

  - Nothing.

### Removed

  - Nothing.

### Fixed

  -
    [#318](https://github.com/zendframework/zend-diactoros/p
    ull/318) fixes the logic for discovering whether an
    HTTPS scheme is in play to be case insensitive when
    comparing header and SAPI values, ensuring no false
    negative lookups occur.

  -
    [#314](https://github.com/zendframework/zend-diactoros/p
    ull/314) modifies error handling around opening a file
    resource within `Zend\Diactoros\Stream::setStream()` to
    no longer use the second argument to
    `set_error_handler()`, and instead check the error type
    in the handler itself; this fixes an issue when the
    handler is nested inside another error handler, which
    currently has buggy behavior within the PHP engine.

## 1.8.1 - 2018-07-09

### Added

  - Nothing.

### Changed

  -
    [#313](https://github.com/zendframework/zend-diactoros/p
    ull/313) changes the reason phrase associated with the
    status code 425 to 'Too Early', corresponding to a new
    definition of the code as specified by the IANA.

### Deprecated

  - Nothing.

### Removed

  - Nothing.

### Fixed

  -
    [#312](https://github.com/zendframework/zend-diactoros/p
    ull/312) fixes how the `normalizeUploadedFiles()`
    utility function handles nested trees of uploaded files,
    ensuring it detects them properly.

## 1.8.0 - 2018-06-27

### Added

  -
    [#307](https://github.com/zendframework/zend-diactoros/p
    ull/307) adds the following functions under the
    `Zend\Diactoros` namespace, each of which may be used to
    derive artifacts from SAPI supergloabls for the purposes
    of generating a `ServerRequest` instance :

  - `normalizeServer(array $server, callable
    $apacheRequestHeaderCallback = null) : array` (main
    purpose is to aggregate the `Authorization` header in
    the SAPI params when under Apache)

  - `marshalProtocolVersionFromSapi(array $server) : string`

  - `marshalMethodFromSapi(array $server) : string`

  - `marshalUriFromSapi(array $server, array $headers) :
    Uri`

  - `marshalHeadersFromSapi(array $server) : array`

  - `parseCookieHeader(string $header) : array`

  - `createUploadedFile(array $spec) : UploadedFile`
    (creates the instance from a normal `$_FILES` entry)

  - `normalizeUploadedFiles(array $files) :
    UploadedFileInterface[]` (traverses a potentially nested
    array of uploaded file instances and/or `$_FILES`
    entries, including those aggregated under mod_php,
    php-fpm, and php-cgi in order to create a flat array of
    `UploadedFileInterface` instances to use in a request)

### Changed

  - Nothing.

### Deprecated

  -
    [#307](https://github.com/zendframework/zend-diactoros/p
    ull/307) deprecates
    `ServerRequestFactory::normalizeServer()`; the method is
    no longer used internally, and users should instead use
    `Zend\Diactoros ormalizeServer()`, to which it proxies.

  -
    [#307](https://github.com/zendframework/zend-diactoros/p
    ull/307) deprecates
    `ServerRequestFactory::marshalHeaders()`; the method is
    no longer used internally, and users should instead use
    `Zend\Diactoros\marshalHeadersFromSapi()`, to which it
    proxies.

  -
    [#307](https://github.com/zendframework/zend-diactoros/p
    ull/307) deprecates
    `ServerRequestFactory::marshalUriFromServer()`; the
    method is no longer used internally. Users should use
    `marshalUriFromSapi()` instead.

  -
    [#307](https://github.com/zendframework/zend-diactoros/p
    ull/307) deprecates
    `ServerRequestFactory::marshalRequestUri()`. the method
    is no longer used internally, and currently proxies to
    `marshalUriFromSapi()`, pulling the discovered path from
    the `Uri` instance returned by that function. Users
    should use `marshalUriFromSapi()` instead.

  -
    [#307](https://github.com/zendframework/zend-diactoros/p
    ull/307) deprecates
    `ServerRequestFactory::marshalHostAndPortFromHeaders()`;
    the method is no longer used internally, and currently
    proxies to `marshalUriFromSapi()`, pulling the
    discovered host and port from the `Uri` instance
    returned by that function. Users should use
    `marshalUriFromSapi()` instead.

  -
    [#307](https://github.com/zendframework/zend-diactoros/p
    ull/307) deprecates `ServerRequestFactory::getHeader()`;
    the method is no longer used internally. Users should
    copy and paste the functionality into their own
    applications if needed, or rely on headers from a
    fully-populated `Uri` instance instead.

  -
    [#307](https://github.com/zendframework/zend-diactoros/p
    ull/307) deprecates
    `ServerRequestFactory::stripQueryString()`; the method
    is no longer used internally, and users can mimic the
    functionality via the expression `$path = explode('?',
    $path, 2)[0];`.

  -
    [#307](https://github.com/zendframework/zend-diactoros/p
    ull/307) deprecates
    `ServerRequestFactory::normalizeFiles()`; the
    functionality is no longer used internally, and users
    can use `normalizeUploadedFiles()` as a replacement.

  -
    [#303](https://github.com/zendframework/zend-diactoros/p
    ull/303) deprecates
    `Zend\Diactoros\Response\EmitterInterface` and its
    various implementations. These are now provided via the
    [zendframework/zend-httphandlerrunner](https://docs.zend
    framework.com/zend-httphandlerrunner) package as 1:1
    substitutions.

  -
    [#303](https://github.com/zendframework/zend-diactoros/p
    ull/303) deprecates the `Zend\Diactoros\Server` class.
    Users are directed to the `RequestHandlerRunner` class
    from the
    [zendframework/zend-httphandlerrunner](https://docs.zend
    framework.com/zend-httphandlerrunner) package as an
    alternative.

### Removed

  - Nothing.

### Fixed

  - Nothing.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-4a606489ae"
  );
  # https://docs.zendframework.com/zend-httphandlerrunner
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.zendframework.com/zend-httphandlerrunner/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/zendframework/zend-diactoros/pull/303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/zendframework/zend-diactoros/pull/307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/zendframework/zend-diactoros/pull/312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/zendframework/zend-diactoros/pull/313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/zendframework/zend-diactoros/pull/314"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/zendframework/zend-diactoros/pull/318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/zendframework/zend-diactoros/pull/319"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/zendframework/zend-diactoros/pull/320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/zendframework/zend-diactoros/pull/321"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php-zendframework-zend-diactoros package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-zendframework-zend-diactoros");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:28");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^28([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 28", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC28", reference:"php-zendframework-zend-diactoros-1.8.4-1.fc28")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-zendframework-zend-diactoros");
}
