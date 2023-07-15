#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125003);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2013-2174",
    "CVE-2014-3707",
    "CVE-2015-3143",
    "CVE-2015-3148",
    "CVE-2016-5420",
    "CVE-2016-7167",
    "CVE-2016-8616",
    "CVE-2016-8619",
    "CVE-2017-1000100",
    "CVE-2017-1000254",
    "CVE-2018-1000007",
    "CVE-2018-1000301"
  );
  script_bugtraq_id(
    60737,
    70988,
    74299,
    74301
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : curl (EulerOS-SA-2019-1550)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the curl packages installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerabilities :

  - curl version curl 7.20.0 to and including curl 7.59.0
    contains a CWE-126: Buffer Over-read vulnerability in
    denial of service that can result in curl can be
    tricked into reading data beyond the end of a heap
    based buffer used to store downloaded RTSP
    content..(CVE-2018-1000301)

  - It was found that the libcurl library did not check the
    client certificate when choosing the TLS connection to
    reuse. An attacker could potentially use this flaw to
    hijack the authentication of the connection by
    leveraging a previously created connection with a
    different client certificate.(CVE-2016-5420)

  - It was discovered that libcurl could incorrectly reuse
    NTLM-authenticated connections for subsequent
    unauthenticated requests to the same host. If an
    application using libcurl established an
    NTLM-authenticated connection to a server, and sent
    subsequent unauthenticated requests to the same server,
    the unauthenticated requests could be sent over the
    NTLM-authenticated connection, appearing as if they
    were sent by the NTLM authenticated
    user.(CVE-2015-3143)

  - libcurl may read outside of a heap allocated buffer
    when doing FTP. When libcurl connects to an FTP server
    and successfully logs in (anonymous or not), it asks
    the server for the current directory with the `PWD`
    command. The server then responds with a 257 response
    containing the path, inside double quotes. The returned
    path name is then kept by libcurl for subsequent uses.
    Due to a flaw in the string parser for this directory
    name, a directory name passed like this but without a
    closing double quote would lead to libcurl not adding a
    trailing NUL byte to the buffer holding the name. When
    libcurl would then later access the string, it could
    read beyond the allocated heap buffer and crash or
    wrongly access data beyond the buffer, thinking it was
    part of the path. A malicious server could abuse this
    fact and effectively prevent libcurl-based clients to
    work with it - the PWD command is always issued on new
    FTP connections and the mistake has a high chance of
    causing a segfault. The simple fact that this has issue
    remained undiscovered for this long could suggest that
    malformed PWD responses are rare in benign servers. We
    are not aware of any exploit of this flaw. This bug was
    introduced in commit
    415d2e7cb7(https://github.com/curl/curl/commit/415d2e7c
    b7), March 2005. In libcurl version 7.56.0, the parser
    always zero terminates the string but also rejects it
    if not terminated properly with a final double
    quote.(CVE-2017-1000254)

  - It was discovered that libcurl could incorrectly reuse
    Negotiate authenticated HTTP connections for subsequent
    requests. If an application using libcurl established a
    Negotiate authenticated HTTP connection to a server and
    sent subsequent requests with different credentials,
    the connection could be re-used with the initial set of
    credentials instead of using the new
    ones.(CVE-2015-3148)

  - Heap-based buffer overflow in the curl_easy_unescape
    function in lib/escape.c in cURL and libcurl 7.7
    through 7.30.0 allows remote attackers to cause a
    denial of service (application crash) or possibly
    execute arbitrary code via a crafted string ending in a
    ''%'' (percent) character.(CVE-2013-2174)

  - ** RESERVED ** This candidate has been reserved by an
    organization or individual that will use it when
    announcing a new security problem. When the candidate
    has been publicized, the details for this candidate
    will be provided.(CVE-2016-8616)

  - ** RESERVED ** This candidate has been reserved by an
    organization or individual that will use it when
    announcing a new security problem. When the candidate
    has been publicized, the details for this candidate
    will be provided.(CVE-2016-8619)

  - It was found that curl and libcurl might send their
    Authentication header to a third party HTTP server upon
    receiving an HTTP REDIRECT reply. This could leak
    authentication token to external
    entities.(CVE-2018-1000007)

  - A flaw was found in the way the libcurl library
    performed the duplication of connection handles. If an
    application set the CURLOPT_COPYPOSTFIELDS option for a
    handle, using the handle's duplicate could cause the
    application to crash or disclose a portion of its
    memory.(CVE-2014-3707)

  - Multiple integer overflow flaws leading to heap-based
    buffer overflows were found in the way curl handled
    escaping and unescaping of data. An attacker could
    potentially use these flaws to crash an application
    using libcurl by sending a specially crafted input to
    the affected libcurl functions.(CVE-2016-7167)

  - When doing a TFTP transfer and curl/libcurl is given a
    URL that contains a very long file name (longer than
    about 515 bytes), the file name is truncated to fit
    within the buffer boundaries, but the buffer size is
    still wrongly updated to use the untruncated length.
    This too large value is then used in the sendto() call,
    making curl attempt to send more data than what is
    actually put into the buffer. The endto() function will
    then read beyond the end of the heap based buffer. A
    malicious HTTP(S) server could redirect a vulnerable
    libcurl-using client to a crafted TFTP URL (if the
    client hasn't restricted which protocols it allows
    redirects to) and trick it to send private memory
    contents to a remote server over UDP. Limit curl's
    redirect protocols with --proto-redir and libcurl's
    with CURLOPT_REDIR_PROTOCOLS.(CVE-2017-1000100)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1550
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?90cc0a91");
  script_set_attribute(attribute:"solution", value:
"Update the affected curl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libcurl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["curl-7.29.0-46.h10",
        "libcurl-7.29.0-46.h10"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl");
}
