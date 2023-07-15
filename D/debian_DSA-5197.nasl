#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5197. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(163681);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2021-22898",
    "CVE-2021-22924",
    "CVE-2021-22945",
    "CVE-2021-22946",
    "CVE-2021-22947",
    "CVE-2022-22576",
    "CVE-2022-27774",
    "CVE-2022-27775",
    "CVE-2022-27776",
    "CVE-2022-27781",
    "CVE-2022-27782",
    "CVE-2022-32205",
    "CVE-2022-32206",
    "CVE-2022-32207",
    "CVE-2022-32208"
  );
  script_xref(name:"IAVA", value:"2022-A-0224-S");
  script_xref(name:"IAVA", value:"2022-A-0255-S");
  script_xref(name:"CEA-ID", value:"CEA-2022-0026");

  script_name(english:"Debian DSA-5197-1 : curl - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5197 advisory.

  - curl 7.7 through 7.76.1 suffers from an information disclosure when the `-t` command line option, known as
    `CURLOPT_TELNETOPTIONS` in libcurl, is used to send variable=content pairs to TELNET servers. Due to a
    flaw in the option parser for sending NEW_ENV variables, libcurl could be made to pass on uninitialized
    data from a stack based buffer to the server, resulting in potentially revealing sensitive internal
    information to the server using a clear-text network protocol. (CVE-2021-22898)

  - libcurl keeps previously used connections in a connection pool for subsequenttransfers to reuse, if one of
    them matches the setup.Due to errors in the logic, the config matching function did not take 'issuercert'
    into account and it compared the involved paths *case insensitively*,which could lead to libcurl reusing
    wrong connections.File paths are, or can be, case sensitive on many systems but not all, and caneven vary
    depending on used file systems.The comparison also didn't include the 'issuer cert' which a transfer can
    setto qualify how to verify the server certificate. (CVE-2021-22924)

  - When sending data to an MQTT server, libcurl <= 7.73.0 and 7.78.0 could in some circumstances erroneously
    keep a pointer to an already freed memory area and both use that again in a subsequent call to send data
    and also free it *again*. (CVE-2021-22945)

  - A user can tell curl >= 7.20.0 and <= 7.78.0 to require a successful upgrade to TLS when speaking to an
    IMAP, POP3 or FTP server (`--ssl-reqd` on the command line or`CURLOPT_USE_SSL` set to `CURLUSESSL_CONTROL`
    or `CURLUSESSL_ALL` withlibcurl). This requirement could be bypassed if the server would return a properly
    crafted but perfectly legitimate response.This flaw would then make curl silently continue its operations
    **withoutTLS** contrary to the instructions and expectations, exposing possibly sensitive data in clear
    text over the network. (CVE-2021-22946)

  - When curl >= 7.20.0 and <= 7.78.0 connects to an IMAP or POP3 server to retrieve data using STARTTLS to
    upgrade to TLS security, the server can respond and send back multiple responses at once that curl caches.
    curl would then upgrade to TLS but not flush the in-queue of cached responses but instead continue using
    and trustingthe responses it got *before* the TLS handshake as if they were authenticated.Using this flaw,
    it allows a Man-In-The-Middle attacker to first inject the fake responses, then pass-through the TLS
    traffic from the legitimate server and trick curl into sending data back to the user thinking the
    attacker's injected data comes from the TLS-protected server. (CVE-2021-22947)

  - An improper authentication vulnerability exists in curl 7.33.0 to and including 7.82.0 which might allow
    reuse OAUTH2-authenticated connections without properly making sure that the connection was authenticated
    with the same credentials as set for this transfer. This affects SASL-enabled protocols: SMPTP(S),
    IMAP(S), POP3(S) and LDAP(S) (openldap only). (CVE-2022-22576)

  - An insufficiently protected credentials vulnerability exists in curl 4.9 to and include curl 7.82.0 are
    affected that could allow an attacker to extract credentials when follows HTTP(S) redirects is used with
    authentication could leak credentials to other services that exist on different protocols or port numbers.
    (CVE-2022-27774)

  - An information disclosure vulnerability exists in curl 7.65.0 to 7.82.0 are vulnerable that by using an
    IPv6 address that was in the connection pool but with a different zone id it could reuse a connection
    instead. (CVE-2022-27775)

  - A insufficiently protected credentials vulnerability in fixed in curl 7.83.0 might leak authentication or
    cookie header data on HTTP redirects to the same host but another port number. (CVE-2022-27776)

  - libcurl provides the `CURLOPT_CERTINFO` option to allow applications torequest details to be returned
    about a server's certificate chain.Due to an erroneous function, a malicious server could make libcurl
    built withNSS get stuck in a never-ending busy-loop when trying to retrieve thatinformation.
    (CVE-2022-27781)

  - libcurl would reuse a previously created connection even when a TLS or SSHrelated option had been changed
    that should have prohibited reuse.libcurl keeps previously used connections in a connection pool for
    subsequenttransfers to reuse if one of them matches the setup. However, several TLS andSSH settings were
    left out from the configuration match checks, making themmatch too easily. (CVE-2022-27782)

  - A malicious server can serve excessive amounts of `Set-Cookie:` headers in a HTTP response to curl and
    curl < 7.84.0 stores all of them. A sufficiently large amount of (big) cookies make subsequent HTTP
    requests to this, or other servers to which the cookies match, create requests that become larger than the
    threshold that curl uses internally to avoid sending crazy large requests (1048576 bytes) and instead
    returns an error.This denial state might remain for as long as the same cookies are kept, match and
    haven't expired. Due to cookie matching rules, a server on `foo.example.com` can set cookies that also
    would match for `bar.example.com`, making it it possible for a sister server to effectively cause a
    denial of service for a sibling site on the same second level domain using this method. (CVE-2022-32205)

  - curl < 7.84.0 supports chained HTTP compression algorithms, meaning that a serverresponse can be
    compressed multiple times and potentially with different algorithms. The number of acceptable links in
    this decompression chain was unbounded, allowing a malicious server to insert a virtually unlimited
    number of compression steps.The use of such a decompression chain could result in a malloc bomb,
    makingcurl end up spending enormous amounts of allocated heap memory, or trying toand returning out of
    memory errors. (CVE-2022-32206)

  - When curl < 7.84.0 saves cookies, alt-svc and hsts data to local files, it makes the operation atomic by
    finalizing the operation with a rename from a temporary name to the final target file name.In that rename
    operation, it might accidentally *widen* the permissions for the target file, leaving the updated file
    accessible to more users than intended. (CVE-2022-32207)

  - When curl < 7.84.0 does FTP transfers secured by krb5, it handles message verification failures wrongly.
    This flaw makes it possible for a Man-In-The-Middle attack to go unnoticed and even allows it to inject
    data to the client. (CVE-2022-32208)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=989228");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/curl");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5197");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-22898");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-22924");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-22945");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-22946");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-22947");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-22576");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-27774");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-27775");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-27776");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-27781");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-27782");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-32205");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-32206");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-32207");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-32208");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/curl");
  script_set_attribute(attribute:"solution", value:
"Upgrade the curl packages.

For the stable distribution (bullseye), these problems have been fixed in version 7.74.0-1.3+deb11u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32207");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl3-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl3-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl4-gnutls-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl4-nss-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl4-openssl-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'curl', 'reference': '7.74.0-1.3+deb11u2'},
    {'release': '11.0', 'prefix': 'libcurl3-gnutls', 'reference': '7.74.0-1.3+deb11u2'},
    {'release': '11.0', 'prefix': 'libcurl3-nss', 'reference': '7.74.0-1.3+deb11u2'},
    {'release': '11.0', 'prefix': 'libcurl4', 'reference': '7.74.0-1.3+deb11u2'},
    {'release': '11.0', 'prefix': 'libcurl4-doc', 'reference': '7.74.0-1.3+deb11u2'},
    {'release': '11.0', 'prefix': 'libcurl4-gnutls-dev', 'reference': '7.74.0-1.3+deb11u2'},
    {'release': '11.0', 'prefix': 'libcurl4-nss-dev', 'reference': '7.74.0-1.3+deb11u2'},
    {'release': '11.0', 'prefix': 'libcurl4-openssl-dev', 'reference': '7.74.0-1.3+deb11u2'}
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
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'curl / libcurl3-gnutls / libcurl3-nss / libcurl4 / libcurl4-doc / etc');
}
