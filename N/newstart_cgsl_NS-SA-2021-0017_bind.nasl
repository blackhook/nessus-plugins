##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0017. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147379);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2006-4095",
    "CVE-2007-2241",
    "CVE-2007-2925",
    "CVE-2007-2926",
    "CVE-2007-6283",
    "CVE-2008-0122",
    "CVE-2008-1447",
    "CVE-2009-0025",
    "CVE-2009-0696",
    "CVE-2010-0213",
    "CVE-2011-1907",
    "CVE-2011-1910",
    "CVE-2011-4313",
    "CVE-2012-1667",
    "CVE-2013-2266",
    "CVE-2013-3919",
    "CVE-2013-4854",
    "CVE-2014-0591",
    "CVE-2019-6471",
    "CVE-2020-8616",
    "CVE-2020-8617",
    "CVE-2020-8622",
    "CVE-2020-8623",
    "CVE-2020-8624"
  );
  script_bugtraq_id(
    19859,
    23738,
    25037,
    25076,
    27283,
    30131,
    33151,
    35848,
    41730,
    47734,
    48007,
    50690,
    53772,
    58736,
    60338,
    61479,
    64801,
    81519,
    108854
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : bind Multiple Vulnerabilities (NS-SA-2021-0017)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has bind packages installed that are affected by
multiple vulnerabilities:

  - In BIND 9.0.0 -> 9.11.21, 9.12.0 -> 9.16.5, 9.17.0 -> 9.17.3, also affects 9.9.3-S1 -> 9.11.21-S1 of the
    BIND 9 Supported Preview Edition, An attacker on the network path for a TSIG-signed request, or operating
    the server receiving the TSIG-signed request, could send a truncated response to that request, triggering
    an assertion failure, causing the server to exit. Alternately, an off-path attacker would have to
    correctly guess when a TSIG-signed request was sent, along with other characteristics of the packet and
    message, and spoof a truncated response to trigger an assertion failure, causing the server to exit.
    (CVE-2020-8622)

  - In BIND 9.10.0 -> 9.11.21, 9.12.0 -> 9.16.5, 9.17.0 -> 9.17.3, also affects 9.10.5-S1 -> 9.11.21-S1 of the
    BIND 9 Supported Preview Edition, An attacker that can reach a vulnerable system with a specially crafted
    query packet can trigger a crash. To be vulnerable, the system must: * be running BIND that was built with
    --enable-native-pkcs11 * be signing one or more zones with an RSA key * be able to receive queries from
    a possible attacker (CVE-2020-8623)

  - In BIND 9.9.12 -> 9.9.13, 9.10.7 -> 9.10.8, 9.11.3 -> 9.11.21, 9.12.1 -> 9.16.5, 9.17.0 -> 9.17.3, also
    affects 9.9.12-S1 -> 9.9.13-S1, 9.11.3-S1 -> 9.11.21-S1 of the BIND 9 Supported Preview Edition, An
    attacker who has been granted privileges to change a specific subset of the zone's content could abuse
    these unintended additional privileges to update other contents of the zone. (CVE-2020-8624)

  - BIND before 9.2.6-P1 and 9.3.x before 9.3.2-P1 allows remote attackers to cause a denial of service
    (crash) via certain SIG queries, which cause an assertion failure when multiple RRsets are returned.
    (CVE-2006-4095)

  - Unspecified vulnerability in query.c in ISC BIND 9.4.0, and 9.5.0a1 through 9.5.0a3, when recursion is
    enabled, allows remote attackers to cause a denial of service (daemon exit) via a sequence of queries
    processed by the query_addsoa function. (CVE-2007-2241)

  - The default access control lists (ACL) in ISC BIND 9.4.0, 9.4.1, and 9.5.0a1 through 9.5.0a5 do not set
    the allow-recursion and allow-query-cache ACLs, which allows remote attackers to make recursive queries
    and query the cache. (CVE-2007-2925)

  - ISC BIND 9 through 9.5.0a5 uses a weak random number generator during generation of DNS query ids when
    answering resolver questions or sending NOTIFY messages to slave name servers, which makes it easier for
    remote attackers to guess the next query id and perform DNS cache poisoning. (CVE-2007-2926)

  - Red Hat Enterprise Linux 5 and Fedora install the Bind /etc/rndc.key file with world-readable permissions,
    which allows local users to perform unauthorized named commands, such as causing a denial of service by
    stopping named. (CVE-2007-6283)

  - Off-by-one error in the inet_network function in libbind in ISC BIND 9.4.2 and earlier, as used in libc in
    FreeBSD 6.2 through 7.0-PRERELEASE, allows context-dependent attackers to cause a denial of service
    (crash) and possibly execute arbitrary code via crafted input that triggers memory corruption.
    (CVE-2008-0122)

  - The DNS protocol, as implemented in (1) BIND 8 and 9 before 9.5.0-P1, 9.4.2-P1, and 9.3.5-P1; (2)
    Microsoft DNS in Windows 2000 SP4, XP SP2 and SP3, and Server 2003 SP1 and SP2; and other implementations
    allow remote attackers to spoof DNS traffic via a birthday attack that uses in-bailiwick referrals to
    conduct cache poisoning against recursive resolvers, related to insufficient randomness of DNS transaction
    IDs and source ports, aka DNS Insufficient Socket Entropy Vulnerability or the Kaminsky bug.
    (CVE-2008-1447)

  - BIND 9.6.0, 9.5.1, 9.5.0, 9.4.3, and earlier does not properly check the return value from the OpenSSL
    DSA_verify function, which allows remote attackers to bypass validation of the certificate chain via a
    malformed SSL/TLS signature, a similar vulnerability to CVE-2008-5077. (CVE-2009-0025)

  - The dns_db_findrdataset function in db.c in named in ISC BIND 9.4 before 9.4.3-P3, 9.5 before 9.5.1-P3,
    and 9.6 before 9.6.1-P1, when configured as a master server, allows remote attackers to cause a denial of
    service (assertion failure and daemon exit) via an ANY record in the prerequisite section of a crafted
    dynamic update message, as exploited in the wild in July 2009. (CVE-2009-0696)

  - BIND 9.7.1 and 9.7.1-P1, when a recursive validating server has a trust anchor that is configured
    statically or via DNSSEC Lookaside Validation (DLV), allows remote attackers to cause a denial of service
    (infinite loop) via a query for an RRSIG record whose answer is not in the cache, which causes BIND to
    repeatedly send RRSIG queries to the authoritative servers. (CVE-2010-0213)

  - ISC BIND 9.8.x before 9.8.0-P1, when Response Policy Zones (RPZ) RRset replacement is enabled, allows
    remote attackers to cause a denial of service (assertion failure and daemon exit) via an RRSIG query.
    (CVE-2011-1907)

  - Off-by-one error in named in ISC BIND 9.x before 9.7.3-P1, 9.8.x before 9.8.0-P2, 9.4-ESV before
    9.4-ESV-R4-P1, and 9.6-ESV before 9.6-ESV-R4-P1 allows remote DNS servers to cause a denial of service
    (assertion failure and daemon exit) via a negative response containing large RRSIG RRsets. (CVE-2011-1910)

  - query.c in ISC BIND 9.0.x through 9.6.x, 9.4-ESV through 9.4-ESV-R5, 9.6-ESV through 9.6-ESV-R5, 9.7.0
    through 9.7.4, 9.8.0 through 9.8.1, and 9.9.0a1 through 9.9.0b1 allows remote attackers to cause a denial
    of service (assertion failure and named exit) via unknown vectors related to recursive DNS queries, error
    logging, and the caching of an invalid record by the resolver. (CVE-2011-4313)

  - ISC BIND 9.x before 9.7.6-P1, 9.8.x before 9.8.3-P1, 9.9.x before 9.9.1-P1, and 9.4-ESV and 9.6-ESV before
    9.6-ESV-R7-P1 does not properly handle resource records with a zero-length RDATA section, which allows
    remote DNS servers to cause a denial of service (daemon crash or data corruption) or obtain sensitive
    information from process memory via a crafted record. (CVE-2012-1667)

  - libdns in ISC BIND 9.7.x and 9.8.x before 9.8.4-P2, 9.8.5 before 9.8.5b2, 9.9.x before 9.9.2-P2, and 9.9.3
    before 9.9.3b2 on UNIX platforms allows remote attackers to cause a denial of service (memory consumption)
    via a crafted regular expression, as demonstrated by a memory-exhaustion attack against a machine running
    a named process. (CVE-2013-2266)

  - resolver.c in ISC BIND 9.8.5 before 9.8.5-P1, 9.9.3 before 9.9.3-P1, and 9.6-ESV-R9 before 9.6-ESV-R9-P1,
    when a recursive resolver is configured, allows remote attackers to cause a denial of service (assertion
    failure and named daemon exit) via a query for a record in a malformed zone. (CVE-2013-3919)

  - The RFC 5011 implementation in rdata.c in ISC BIND 9.7.x and 9.8.x before 9.8.5-P2, 9.8.6b1, 9.9.x before
    9.9.3-P2, and 9.9.4b1, and DNSco BIND 9.9.3-S1 before 9.9.3-S1-P1 and 9.9.4-S1b1, allows remote attackers
    to cause a denial of service (assertion failure and named daemon exit) via a query with a malformed RDATA
    section that is not properly handled during construction of a log message, as exploited in the wild in
    July 2013. (CVE-2013-4854)

  - The query_findclosestnsec3 function in query.c in named in ISC BIND 9.6, 9.7, and 9.8 before 9.8.6-P2 and
    9.9 before 9.9.4-P2, and 9.6-ESV before 9.6-ESV-R10-P2, allows remote attackers to cause a denial of
    service (INSIST assertion failure and daemon exit) via a crafted DNS query to an authoritative nameserver
    that uses the NSEC3 signing feature. (CVE-2014-0591)

  - A race condition which may occur when discarding malformed packets can result in BIND exiting due to a
    REQUIRE assertion failure in dispatch.c. Versions affected: BIND 9.11.0 -> 9.11.7, 9.12.0 -> 9.12.4-P1,
    9.14.0 -> 9.14.2. Also all releases of the BIND 9.13 development branch and version 9.15.0 of the BIND
    9.15 development branch and BIND Supported Preview Edition versions 9.11.3-S1 -> 9.11.7-S1.
    (CVE-2019-6471)

  - A malicious actor who intentionally exploits this lack of effective limitation on the number of fetches
    performed when processing referrals can, through the use of specially crafted referrals, cause a recursing
    server to issue a very large number of fetches in an attempt to process the referral. This has at least
    two potential effects: The performance of the recursing server can potentially be degraded by the
    additional work required to perform these fetches, and The attacker can exploit this behavior to use the
    recursing server as a reflector in a reflection attack with a high amplification factor. (CVE-2020-8616)

  - Using a specially-crafted message, an attacker may potentially cause a BIND server to reach an
    inconsistent state if the attacker knows (or successfully guesses) the name of a TSIG key used by the
    server. Since BIND, by default, configures a local session key even on servers whose configuration does
    not otherwise make use of it, almost all current BIND servers are vulnerable. In releases of BIND dating
    from March 2018 and after, an assertion check in tsig.c detects this inconsistent state and deliberately
    exits. Prior to the introduction of the check the server would continue operating in an inconsistent
    state, with potentially harmful results. (CVE-2020-8617)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0017");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL bind packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-0122");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2008-1447");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/05");
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
    'bind-9.11.4-26.P2.el7_9.2.cgslv5.0.1.gd99f173',
    'bind-chroot-9.11.4-26.P2.el7_9.2.cgslv5.0.1.gd99f173',
    'bind-debuginfo-9.11.4-26.P2.el7_9.2.cgslv5.0.1.gd99f173',
    'bind-devel-9.11.4-26.P2.el7_9.2.cgslv5.0.1.gd99f173',
    'bind-export-devel-9.11.4-26.P2.el7_9.2.cgslv5.0.1.gd99f173',
    'bind-export-libs-9.11.4-26.P2.el7_9.2.cgslv5.0.1.gd99f173',
    'bind-libs-9.11.4-26.P2.el7_9.2.cgslv5.0.1.gd99f173',
    'bind-libs-lite-9.11.4-26.P2.el7_9.2.cgslv5.0.1.gd99f173',
    'bind-license-9.11.4-26.P2.el7_9.2.cgslv5.0.1.gd99f173',
    'bind-lite-devel-9.11.4-26.P2.el7_9.2.cgslv5.0.1.gd99f173',
    'bind-pkcs11-9.11.4-26.P2.el7_9.2.cgslv5.0.1.gd99f173',
    'bind-pkcs11-devel-9.11.4-26.P2.el7_9.2.cgslv5.0.1.gd99f173',
    'bind-pkcs11-libs-9.11.4-26.P2.el7_9.2.cgslv5.0.1.gd99f173',
    'bind-pkcs11-utils-9.11.4-26.P2.el7_9.2.cgslv5.0.1.gd99f173',
    'bind-sdb-9.11.4-26.P2.el7_9.2.cgslv5.0.1.gd99f173',
    'bind-sdb-chroot-9.11.4-26.P2.el7_9.2.cgslv5.0.1.gd99f173',
    'bind-utils-9.11.4-26.P2.el7_9.2.cgslv5.0.1.gd99f173'
  ],
  'CGSL MAIN 5.04': [
    'bind-9.11.4-26.P2.el7_9.2.cgslv5.0.1.gd99f173',
    'bind-chroot-9.11.4-26.P2.el7_9.2.cgslv5.0.1.gd99f173',
    'bind-debuginfo-9.11.4-26.P2.el7_9.2.cgslv5.0.1.gd99f173',
    'bind-devel-9.11.4-26.P2.el7_9.2.cgslv5.0.1.gd99f173',
    'bind-export-devel-9.11.4-26.P2.el7_9.2.cgslv5.0.1.gd99f173',
    'bind-export-libs-9.11.4-26.P2.el7_9.2.cgslv5.0.1.gd99f173',
    'bind-libs-9.11.4-26.P2.el7_9.2.cgslv5.0.1.gd99f173',
    'bind-libs-lite-9.11.4-26.P2.el7_9.2.cgslv5.0.1.gd99f173',
    'bind-license-9.11.4-26.P2.el7_9.2.cgslv5.0.1.gd99f173',
    'bind-lite-devel-9.11.4-26.P2.el7_9.2.cgslv5.0.1.gd99f173',
    'bind-pkcs11-9.11.4-26.P2.el7_9.2.cgslv5.0.1.gd99f173',
    'bind-pkcs11-devel-9.11.4-26.P2.el7_9.2.cgslv5.0.1.gd99f173',
    'bind-pkcs11-libs-9.11.4-26.P2.el7_9.2.cgslv5.0.1.gd99f173',
    'bind-pkcs11-utils-9.11.4-26.P2.el7_9.2.cgslv5.0.1.gd99f173',
    'bind-sdb-9.11.4-26.P2.el7_9.2.cgslv5.0.1.gd99f173',
    'bind-sdb-chroot-9.11.4-26.P2.el7_9.2.cgslv5.0.1.gd99f173',
    'bind-utils-9.11.4-26.P2.el7_9.2.cgslv5.0.1.gd99f173'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind');
}
