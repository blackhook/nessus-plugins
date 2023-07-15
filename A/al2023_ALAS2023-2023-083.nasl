#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2023-083.
##

include('compat.inc');

if (description)
{
  script_id(173171);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/20");

  script_cve_id(
    "CVE-2022-22576",
    "CVE-2022-27774",
    "CVE-2022-27775",
    "CVE-2022-27776",
    "CVE-2022-27779",
    "CVE-2022-27780",
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
    "CVE-2022-42916",
    "CVE-2022-43551",
    "CVE-2022-43552"
  );
  script_xref(name:"IAVA", value:"2022-A-0451-S");
  script_xref(name:"IAVA", value:"2023-A-0008-S");
  script_xref(name:"IAVA", value:"2022-A-0224-S");
  script_xref(name:"IAVA", value:"2022-A-0255-S");
  script_xref(name:"IAVA", value:"2022-A-0350-S");
  script_xref(name:"CEA-ID", value:"CEA-2022-0026");

  script_name(english:"Amazon Linux 2023 : curl, curl-minimal, libcurl (ALAS2023-2023-083)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2023-083 advisory.

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

  - A vulnerability exists in curl <7.87.0 HSTS check that could be bypassed to trick it to keep using HTTP.
    Using its HSTS support, curl can be instructed to use HTTPS instead of using an insecure clear-text HTTP
    step even when HTTP is provided in the URL. However, the HSTS mechanism could be bypassed if the host name
    in the given URL first uses IDN characters that get replaced to ASCII counterparts as part of the IDN
    conversion. Like using the character UTF-8 U+3002 (IDEOGRAPHIC FULL STOP) instead of the common ASCII full
    stop (U+002E) `.`. Then in a subsequent request, it does not detect the HSTS state and makes a clear text
    transfer. Because it would store the info IDN encoded but look for it IDN decoded. (CVE-2022-43551)

  - A use after free vulnerability exists in curl <7.87.0. Curl can be asked to *tunnel* virtually all
    protocols it supports through an HTTP proxy. HTTP proxies can (and often do) deny such tunnel operations.
    When getting denied to tunnel the specific protocols SMB or TELNET, curl would use a heap-allocated struct
    after it had been freed, in its transfer shutdown code path. (CVE-2022-43552)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2023-083.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-22576.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27774.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27775.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27776.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27779.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27780.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27782.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-30115.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32205.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32206.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32207.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32208.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32221.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-35252.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-35260.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-42915.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-42916.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-43551.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-43552.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update curl --releasever=2023.0.20230222 ' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32207");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-42915");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl-minimal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl-minimal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2023");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "-2023")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2023", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'curl-7.87.0-2.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-7.87.0-2.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-7.87.0-2.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-debuginfo-7.87.0-2.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-debuginfo-7.87.0-2.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-debuginfo-7.87.0-2.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-debugsource-7.87.0-2.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-debugsource-7.87.0-2.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-debugsource-7.87.0-2.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-minimal-7.87.0-2.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-minimal-7.87.0-2.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-minimal-7.87.0-2.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-minimal-debuginfo-7.87.0-2.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-minimal-debuginfo-7.87.0-2.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-minimal-debuginfo-7.87.0-2.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-7.87.0-2.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-7.87.0-2.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-7.87.0-2.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-debuginfo-7.87.0-2.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-debuginfo-7.87.0-2.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-debuginfo-7.87.0-2.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-devel-7.87.0-2.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-devel-7.87.0-2.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-devel-7.87.0-2.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-minimal-7.87.0-2.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-minimal-7.87.0-2.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-minimal-7.87.0-2.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-minimal-debuginfo-7.87.0-2.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-minimal-debuginfo-7.87.0-2.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-minimal-debuginfo-7.87.0-2.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / curl-debuginfo / curl-debugsource / etc");
}