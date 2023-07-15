#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202212-01.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(168911);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/19");

  script_cve_id(
    "CVE-2021-22922",
    "CVE-2021-22923",
    "CVE-2021-22925",
    "CVE-2021-22926",
    "CVE-2021-22945",
    "CVE-2021-22946",
    "CVE-2021-22947",
    "CVE-2022-22576",
    "CVE-2022-27774",
    "CVE-2022-27775",
    "CVE-2022-27776",
    "CVE-2022-27779",
    "CVE-2022-27780",
    "CVE-2022-27781",
    "CVE-2022-27782",
    "CVE-2022-30115",
    "CVE-2022-32205",
    "CVE-2022-32206",
    "CVE-2022-32207",
    "CVE-2022-32208",
    "CVE-2022-32221",
    "CVE-2022-35252",
    "CVE-2022-35260",
    "CVE-2022-42915",
    "CVE-2022-42916"
  );
  script_xref(name:"CEA-ID", value:"CEA-2022-0026");

  script_name(english:"GLSA-202212-01 : curl: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202212-01 (curl: Multiple Vulnerabilities)

  - When curl is instructed to download content using the metalink feature, thecontents is verified against a
    hash provided in the metalink XML file.The metalink XML file points out to the client how to get the same
    contentfrom a set of different URLs, potentially hosted by different servers and theclient can then
    download the file from one or several of them. In a serial orparallel manner.If one of the servers hosting
    the contents has been breached and the contentsof the specific file on that server is replaced with a
    modified payload, curlshould detect this when the hash of the file mismatches after a completeddownload.
    It should remove the contents and instead try getting the contentsfrom another URL. This is not done, and
    instead such a hash mismatch is onlymentioned in text and the potentially malicious content is kept in the
    file ondisk. (CVE-2021-22922)

  - When curl is instructed to get content using the metalink feature, and a user name and password are used
    to download the metalink XML file, those same credentials are then subsequently passed on to each of the
    servers from which curl will download or try to download the contents from. Often contrary to the user's
    expectations and intentions and without telling the user it happened. (CVE-2021-22923)

  - curl supports the `-t` command line option, known as `CURLOPT_TELNETOPTIONS`in libcurl. This rarely used
    option is used to send variable=content pairs toTELNET servers.Due to flaw in the option parser for
    sending `NEW_ENV` variables, libcurlcould be made to pass on uninitialized data from a stack based buffer
    to theserver. Therefore potentially revealing sensitive internal information to theserver using a clear-
    text network protocol.This could happen because curl did not call and use sscanf() correctly whenparsing
    the string provided by the application. (CVE-2021-22925)

  - libcurl-using applications can ask for a specific client certificate to be used in a transfer. This is
    done with the `CURLOPT_SSLCERT` option (`--cert` with the command line tool).When libcurl is built to use
    the macOS native TLS library Secure Transport, an application can ask for the client certificate by name
    or with a file name - using the same option. If the name exists as a file, it will be used instead of by
    name.If the appliction runs with a current working directory that is writable by other users (like
    `/tmp`), a malicious user can create a file name with the same name as the app wants to use by name, and
    thereby trick the application to use the file based cert instead of the one referred to by name making
    libcurl send the wrong client certificate in the TLS connection handshake. (CVE-2021-22926)

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

  - libcurl wrongly allows cookies to be set for Top Level Domains (TLDs) if thehost name is provided with a
    trailing dot.curl can be told to receive and send cookies. curl's cookie engine can bebuilt with or
    without [Public Suffix List](https://publicsuffix.org/)awareness. If PSL support not provided, a more
    rudimentary check exists to atleast prevent cookies from being set on TLDs. This check was broken if
    thehost name in the URL uses a trailing dot.This can allow arbitrary sites to set cookies that then would
    get sent to adifferent and unrelated site or domain. (CVE-2022-27779)

  - The curl URL parser wrongly accepts percent-encoded URL separators like '/'when decoding the host name
    part of a URL, making it a *different* URL usingthe wrong host name when it is later retrieved.For
    example, a URL like `http://example.com%2F127.0.0.1/`, would be allowed bythe parser and get transposed
    into `http://example.com/127.0.0.1/`. This flawcan be used to circumvent filters, checks and more.
    (CVE-2022-27780)

  - libcurl provides the `CURLOPT_CERTINFO` option to allow applications torequest details to be returned
    about a server's certificate chain.Due to an erroneous function, a malicious server could make libcurl
    built withNSS get stuck in a never-ending busy-loop when trying to retrieve thatinformation.
    (CVE-2022-27781)

  - libcurl would reuse a previously created connection even when a TLS or SSHrelated option had been changed
    that should have prohibited reuse.libcurl keeps previously used connections in a connection pool for
    subsequenttransfers to reuse if one of them matches the setup. However, several TLS andSSH settings were
    left out from the configuration match checks, making themmatch too easily. (CVE-2022-27782)

  - Using its HSTS support, curl can be instructed to use HTTPS directly insteadof using an insecure clear-
    text HTTP step even when HTTP is provided in theURL. This mechanism could be bypassed if the host name in
    the given URL used atrailing dot while not using one when it built the HSTS cache. Or the otherway around
    - by having the trailing dot in the HSTS cache and *not* using thetrailing dot in the URL.
    (CVE-2022-30115)

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

  - When doing HTTP(S) transfers, libcurl might erroneously use the read callback (`CURLOPT_READFUNCTION`) to
    ask for data to send, even when the `CURLOPT_POSTFIELDS` option has been set, if the same handle
    previously was used to issue a `PUT` request which used that callback. This flaw may surprise the
    application and cause it to misbehave and either send off the wrong data or use memory after free or
    similar in the subsequent `POST` request. The problem exists in the logic for a reused handle when it is
    changed from a PUT to a POST. (CVE-2022-32221)

  - When curl is used to retrieve and parse cookies from a HTTP(S) server, itaccepts cookies using control
    codes that when later are sent back to a HTTPserver might make the server return 400 responses.
    Effectively allowing asister site to deny service to all siblings. (CVE-2022-35252)

  - curl can be told to parse a `.netrc` file for credentials. If that file endsin a line with 4095
    consecutive non-white space letters and no newline, curlwould first read past the end of the stack-based
    buffer, and if the readworks, write a zero byte beyond its boundary.This will in most cases cause a
    segfault or similar, but circumstances might also cause different outcomes.If a malicious user can provide
    a custom netrc file to an application or otherwise affect its contents, this flaw could be used as denial-
    of-service. (CVE-2022-35260)

  - curl before 7.86.0 has a double free. If curl is told to use an HTTP proxy for a transfer with a non-
    HTTP(S) URL, it sets up the connection to the remote server by issuing a CONNECT request to the proxy, and
    then tunnels the rest of the protocol through. An HTTP proxy might refuse this request (HTTP proxies often
    only allow outgoing connections to specific port numbers, like 443 for HTTPS) and instead return a non-200
    status code to the client. Due to flaws in the error/cleanup handling, this could trigger a double free in
    curl if one of the following schemes were used in the URL for the transfer: dict, gopher, gophers, ldap,
    ldaps, rtmp, rtmps, or telnet. The earliest affected version is 7.77.0. (CVE-2022-42915)

  - In curl before 7.86.0, the HSTS check could be bypassed to trick it into staying with HTTP. Using its HSTS
    support, curl can be instructed to use HTTPS directly (instead of using an insecure cleartext HTTP step)
    even when HTTP is provided in the URL. This mechanism could be bypassed if the host name in the given URL
    uses IDN characters that get replaced with ASCII counterparts as part of the IDN conversion, e.g., using
    the character UTF-8 U+3002 (IDEOGRAPHIC FULL STOP) instead of the common ASCII full stop of U+002E (.).
    The earliest affected version is 7.77.0 2021-05-26. (CVE-2022-42916)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202212-01");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=803308");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=813270");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=841302");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=843824");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=854708");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=867679");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=878365");
  script_set_attribute(attribute:"solution", value:
"All curl users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=net-misc/curl-7.86.0");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32207");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-42915");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:curl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'net-misc/curl',
    'unaffected' : make_list("ge 7.86.0"),
    'vulnerable' : make_list("lt 7.86.0")
  }
];

foreach var package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'curl');
}
