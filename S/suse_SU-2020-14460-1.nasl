#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2020:14460-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150657);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2019-12519",
    "CVE-2019-12520",
    "CVE-2019-12521",
    "CVE-2019-12523",
    "CVE-2019-12524",
    "CVE-2019-12525",
    "CVE-2019-12526",
    "CVE-2019-12528",
    "CVE-2019-12529",
    "CVE-2019-13345",
    "CVE-2019-18676",
    "CVE-2019-18677",
    "CVE-2019-18678",
    "CVE-2019-18679",
    "CVE-2019-18860",
    "CVE-2020-8449",
    "CVE-2020-8450",
    "CVE-2020-8517",
    "CVE-2020-11945",
    "CVE-2020-14059",
    "CVE-2020-15049"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2020:14460-1");

  script_name(english:"SUSE SLES11 Security Update : squid3 (SUSE-SU-2020:14460-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has a package installed that is affected by multiple vulnerabilities as referenced in
the SUSE-SU-2020:14460-1 advisory.

  - An issue was discovered in Squid through 4.7. When handling the tag esi:when when ESI is enabled, Squid
    calls ESIExpression::Evaluate. This function uses a fixed stack buffer to hold the expression while it's
    being evaluated. When processing the expression, it could either evaluate the top of the stack, or add a
    new member to the stack. When adding a new member, there is no check to ensure that the stack won't
    overflow. (CVE-2019-12519)

  - An issue was discovered in Squid through 4.7 and 5. When receiving a request, Squid checks its cache to
    see if it can serve up a response. It does this by making a MD5 hash of the absolute URL of the request.
    If found, it servers the request. The absolute URL can include the decoded UserInfo (username and
    password) for certain protocols. This decoded info is prepended to the domain. This allows an attacker to
    provide a username that has special characters to delimit the domain, and treat the rest of the URL as a
    path or query string. An attacker could first make a request to their domain using an encoded username,
    then when a request for the target domain comes in that decodes to the exact URL, it will serve the
    attacker's HTML instead of the real HTML. On Squid servers that also act as reverse proxies, this allows
    an attacker to gain access to features that only reverse proxies can use, such as ESI. (CVE-2019-12520)

  - An issue was discovered in Squid through 4.7. When Squid is parsing ESI, it keeps the ESI elements in
    ESIContext. ESIContext contains a buffer for holding a stack of ESIElements. When a new ESIElement is
    parsed, it is added via addStackElement. addStackElement has a check for the number of elements in this
    buffer, but it's off by 1, leading to a Heap Overflow of 1 element. The overflow is within the same
    structure so it can't affect adjacent memory blocks, and thus just leads to a crash while processing.
    (CVE-2019-12521)

  - An issue was discovered in Squid before 4.9. When handling a URN request, a corresponding HTTP request is
    made. This HTTP request doesn't go through the access checks that incoming HTTP requests go through. This
    causes all access checks to be bypassed and allows access to restricted HTTP servers, e.g., an attacker
    can connect to HTTP servers that only listen on localhost. (CVE-2019-12523)

  - An issue was discovered in Squid through 4.7. When handling requests from users, Squid checks its rules to
    see if the request should be denied. Squid by default comes with rules to block access to the Cache
    Manager, which serves detailed server information meant for the maintainer. This rule is implemented via
    url_regex. The handler for url_regex rules URL decodes an incoming request. This allows an attacker to
    encode their URL to bypass the url_regex check, and gain access to the blocked resource. (CVE-2019-12524)

  - An issue was discovered in Squid 3.3.9 through 3.5.28 and 4.x through 4.7. When Squid is configured to use
    Digest authentication, it parses the header Proxy-Authorization. It searches for certain tokens such as
    domain, uri, and qop. Squid checks if this token's value starts with a quote and ends with one. If so, it
    performs a memcpy of its length minus 2. Squid never checks whether the value is just a single quote
    (which would satisfy its requirements), leading to a memcpy of its length minus 1. (CVE-2019-12525)

  - An issue was discovered in Squid before 4.9. URN response handling in Squid suffers from a heap-based
    buffer overflow. When receiving data from a remote server in response to an URN request, Squid fails to
    ensure that the response can fit within the buffer. This leads to attacker controlled data overflowing in
    the heap. (CVE-2019-12526)

  - An issue was discovered in Squid before 4.10. It allows a crafted FTP server to trigger disclosure of
    sensitive information from heap memory, such as information associated with other users' sessions or non-
    Squid processes. (CVE-2019-12528)

  - An issue was discovered in Squid 2.x through 2.7.STABLE9, 3.x through 3.5.28, and 4.x through 4.7. When
    Squid is configured to use Basic Authentication, the Proxy-Authorization header is parsed via uudecode.
    uudecode determines how many bytes will be decoded by iterating over the input and checking its table. The
    length is then used to start decoding the string. There are no checks to ensure that the length it
    calculates isn't greater than the input buffer. This leads to adjacent memory being decoded as well. An
    attacker would not be able to retrieve the decoded data unless the Squid maintainer had configured the
    display of usernames on error pages. (CVE-2019-12529)

  - The cachemgr.cgi web module of Squid through 4.7 has XSS via the user_name or auth parameter.
    (CVE-2019-13345)

  - An issue was discovered in Squid 3.x and 4.x through 4.8. Due to incorrect input validation, there is a
    heap-based buffer overflow that can result in Denial of Service to all clients using the proxy. Severity
    is high due to this vulnerability occurring before normal security checks; any remote client that can
    reach the proxy port can trivially perform the attack via a crafted URI scheme. (CVE-2019-18676)

  - An issue was discovered in Squid 3.x and 4.x through 4.8 when the append_domain setting is used (because
    the appended characters do not properly interact with hostname length restrictions). Due to incorrect
    message processing, it can inappropriately redirect traffic to origins it should not be delivered to.
    (CVE-2019-18677)

  - An issue was discovered in Squid 3.x and 4.x through 4.8. It allows attackers to smuggle HTTP requests
    through frontend software to a Squid instance that splits the HTTP Request pipeline differently. The
    resulting Response messages corrupt caches (between a client and Squid) with attacker-controlled content
    at arbitrary URLs. Effects are isolated to software between the attacker client and Squid. There are no
    effects on Squid itself, nor on any upstream servers. The issue is related to a request header containing
    whitespace between a header name and a colon. (CVE-2019-18678)

  - An issue was discovered in Squid 2.x, 3.x, and 4.x through 4.8. Due to incorrect data management, it is
    vulnerable to information disclosure when processing HTTP Digest Authentication. Nonce tokens contain the
    raw byte value of a pointer that sits within heap memory allocation. This information reduces ASLR
    protections and may aid attackers isolating memory areas to target for remote code execution attacks.
    (CVE-2019-18679)

  - Squid before 4.9, when certain web browsers are used, mishandles HTML in the host (aka hostname) parameter
    to cachemgr.cgi. (CVE-2019-18860)

  - An issue was discovered in Squid before 5.0.2. A remote attacker can replay a sniffed Digest
    Authentication nonce to gain access to resources that are otherwise forbidden. This occurs because the
    attacker can overflow the nonce reference counter (a short integer). Remote code execution may occur if
    the pooled token credentials are freed (instead of replayed as valid credentials). (CVE-2020-11945)

  - An issue was discovered in Squid 5.x before 5.0.3. Due to an Incorrect Synchronization, a Denial of
    Service can occur when processing objects in an SMP cache because of an Ipc::Mem::PageStack::pop ABA
    problem during access to the memory page/slot management list. (CVE-2020-14059)

  - An issue was discovered in http/ContentLengthInterpreter.cc in Squid before 4.12 and 5.x before 5.0.3. A
    Request Smuggling and Poisoning attack can succeed against the HTTP cache. The client sends an HTTP
    request with a Content-Length header containing +\ - or an uncommon shell whitespace character prefix
    to the length field-value. (CVE-2020-15049)

  - An issue was discovered in Squid before 4.10. Due to incorrect input validation, it can interpret crafted
    HTTP requests in unexpected ways to access server resources prohibited by earlier security filters.
    (CVE-2020-8449)

  - An issue was discovered in Squid before 4.10. Due to incorrect buffer management, a remote client can
    cause a buffer overflow in a Squid instance acting as a reverse proxy. (CVE-2020-8450)

  - An issue was discovered in Squid before 4.10. Due to incorrect input validation, the NTLM authentication
    credentials parser in ext_lm_group_acl may write to memory outside the credentials buffer. On systems with
    memory access protections, this can result in the helper process being terminated unexpectedly. This leads
    to the Squid process also terminating and a denial of service for all clients using the proxy.
    (CVE-2020-8517)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1140738");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1141329");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1141332");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1156323");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1156324");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1156326");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1156328");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1156329");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1162687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1162689");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1162691");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1167373");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1169659");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1170313");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1170423");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1173304");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1173455");
  # https://lists.suse.com/pipermail/sle-security-updates/2020-August/007289.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d14abea9");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-12519");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-12520");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-12521");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-12523");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-12524");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-12525");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-12526");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-12528");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-12529");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-13345");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-18676");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-18677");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-18678");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-18679");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-18860");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-11945");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14059");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-15049");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-8449");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-8450");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-8517");
  script_set_attribute(attribute:"solution", value:
"Update the affected squid3 package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8450");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-11945");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:squid3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES11', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);

pkgs = [
    {'reference':'squid3-3.1.23-8.16.37.12', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'squid3-3.1.23-8.16.37.12', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  exists_check = NULL;
  rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release && exists_check) {
    if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
  else if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'squid3');
}
