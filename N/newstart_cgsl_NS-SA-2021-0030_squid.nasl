##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0030. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147395);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2019-12528",
    "CVE-2020-8449",
    "CVE-2020-8450",
    "CVE-2020-15049",
    "CVE-2020-15810",
    "CVE-2020-15811",
    "CVE-2020-24606"
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : squid Multiple Vulnerabilities (NS-SA-2021-0030)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has squid packages installed that are affected by
multiple vulnerabilities:

  - An issue was discovered in Squid before 4.10. It allows a crafted FTP server to trigger disclosure of
    sensitive information from heap memory, such as information associated with other users' sessions or non-
    Squid processes. (CVE-2019-12528)

  - An issue was discovered in Squid before 4.10. Due to incorrect input validation, it can interpret crafted
    HTTP requests in unexpected ways to access server resources prohibited by earlier security filters.
    (CVE-2020-8449)

  - An issue was discovered in Squid before 4.10. Due to incorrect buffer management, a remote client can
    cause a buffer overflow in a Squid instance acting as a reverse proxy. (CVE-2020-8450)

  - An issue was discovered in http/ContentLengthInterpreter.cc in Squid before 4.12 and 5.x before 5.0.3. A
    Request Smuggling and Poisoning attack can succeed against the HTTP cache. The client sends an HTTP
    request with a Content-Length header containing +\ - or an uncommon shell whitespace character prefix
    to the length field-value. (CVE-2020-15049)

  - Squid before 4.13 and 5.x before 5.0.4 allows a trusted peer to perform Denial of Service by consuming all
    available CPU cycles during handling of a crafted Cache Digest response message. This only occurs when
    cache_peer is used with the cache digests feature. The problem exists because peerDigestHandleReply()
    livelocking in peer_digest.cc mishandles EOF. (CVE-2020-24606)

  - An issue was discovered in Squid before 4.13 and 5.x before 5.0.4. Due to incorrect data validation, HTTP
    Request Smuggling attacks may succeed against HTTP and HTTPS traffic. This leads to cache poisoning. This
    allows any client, including browser scripts, to bypass local security and poison the proxy cache and any
    downstream caches with content from an arbitrary source. When configured for relaxed header parsing (the
    default), Squid relays headers containing whitespace characters to upstream servers. When this occurs as a
    prefix to a Content-Length header, the frame length specified will be ignored by Squid (allowing for a
    conflicting length to be used from another Content-Length header) but relayed upstream. (CVE-2020-15810)

  - An issue was discovered in Squid before 4.13 and 5.x before 5.0.4. Due to incorrect data validation, HTTP
    Request Splitting attacks may succeed against HTTP and HTTPS traffic. This leads to cache poisoning. This
    allows any client, including browser scripts, to bypass local security and poison the browser cache and
    any downstream caches with content from an arbitrary source. Squid uses a string search instead of parsing
    the Transfer-Encoding header to find chunked encoding. This allows an attacker to hide a second request
    inside Transfer-Encoding: it is interpreted by Squid as chunked and split out into a second request
    delivered upstream. Squid will then deliver two distinct responses to the client, corrupting any
    downstream caches. (CVE-2020-15811)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0030");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL squid packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8450");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-15049");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL CORE 5.04': [
    'squid-3.5.20-17.el7_9.5',
    'squid-migration-script-3.5.20-17.el7_9.5',
    'squid-sysvinit-3.5.20-17.el7_9.5'
  ],
  'CGSL MAIN 5.04': [
    'squid-3.5.20-17.el7_9.5',
    'squid-migration-script-3.5.20-17.el7_9.5',
    'squid-sysvinit-3.5.20-17.el7_9.5'
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'squid');
}
