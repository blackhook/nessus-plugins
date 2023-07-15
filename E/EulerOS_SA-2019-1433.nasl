#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124936);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2014-0591",
    "CVE-2014-8500",
    "CVE-2015-1349",
    "CVE-2015-4620",
    "CVE-2015-5477",
    "CVE-2015-5722",
    "CVE-2015-8000",
    "CVE-2016-1285",
    "CVE-2016-1286",
    "CVE-2016-2775",
    "CVE-2016-2776",
    "CVE-2016-8864",
    "CVE-2016-9131",
    "CVE-2017-3136",
    "CVE-2017-3142",
    "CVE-2017-3143",
    "CVE-2017-3145",
    "CVE-2018-5740"
  );
  script_bugtraq_id(
    64801,
    71590,
    72673,
    75588
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : bind (EulerOS-SA-2019-1433)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the bind packages installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerabilities :

  - A denial of service flaw was found in the way BIND
    constructed a response to a query that met certain
    criteria. A remote attacker could use this flaw to make
    named exit unexpectedly with an assertion failure via a
    specially crafted DNS request packet.(CVE-2016-2776)

  - A denial of service flaw was found in the way BIND
    processed certain control channel input. A remote
    attacker able to send a malformed packet to the control
    channel could use this flaw to cause named to
    crash.(CVE-2016-1285)

  - A flaw was found in the way BIND performed DNSSEC
    validation. An attacker able to make BIND (functioning
    as a DNS resolver with DNSSEC validation enabled)
    resolve a name in an attacker-controlled domain could
    cause named to exit unexpectedly with an assertion
    failure.(CVE-2015-4620)

  - A flaw was found in the way BIND handled requests for
    TKEY DNS resource records. A remote attacker could use
    this flaw to make named (functioning as an
    authoritative DNS server or a DNS resolver) exit
    unexpectedly with an assertion failure via a specially
    crafted DNS request packet.(CVE-2015-5477)

  - A denial of service flaw was found in the way BIND
    handled queries for NSEC3-signed zones. A remote
    attacker could use this flaw against an authoritative
    name server that served NCES3-signed zones by sending a
    specially crafted query, which, when processed, would
    cause named to crash.(CVE-2014-0591)

  - A denial of service flaw was found in the way BIND
    parsed certain malformed DNSSEC keys. A remote attacker
    could use this flaw to send a specially crafted DNS
    query (for example, a query requiring a response from a
    zone containing a deliberately malformed key) that
    would cause named functioning as a validating resolver
    to crash.(CVE-2015-5722)

  - It was found that the lightweight resolver protocol
    implementation in BIND could enter an infinite
    recursion and crash when asked to resolve a query name
    which, when combined with a search list entry, exceeds
    the maximum allowable length. A remote attacker could
    use this flaw to crash lwresd or named when using the
    'lwres' statement in named.conf.(CVE-2016-2775)

  - A denial of service flaw was found in the way BIND
    processed certain records with malformed class
    attributes. A remote attacker could use this flaw to
    send a query to request a cached record with a
    malformed class attribute that would cause named
    functioning as an authoritative or recursive server to
    crash. Note: This issue affects authoritative servers
    as well as recursive servers, however authoritative
    servers are at limited risk if they perform
    authentication when making recursive queries to resolve
    addresses for servers listed in NS
    RRSETs.(CVE-2015-8000)

  - A denial of service flaw was found in the way BIND
    handled responses containing a DNAME answer. A remote
    attacker could use this flaw to make named exit
    unexpectedly with an assertion failure via a specially
    crafted DNS response.(CVE-2016-8864)

  - A denial of service flaw was found in the way BIND
    processed a response to an ANY query. A remote attacker
    could use this flaw to make named exit unexpectedly
    with an assertion failure via a specially crafted DNS
    response.(CVE-2016-9131)

  - A denial of service flaw was found in the way BIND
    followed DNS delegations. A remote attacker could use a
    specially crafted zone containing a large number of
    referrals which, when looked up and processed, would
    cause named to use excessive amounts of memory or
    crash.(CVE-2014-8500)

  - A flaw was found in the way BIND handled trust anchor
    management. A remote attacker could use this flaw to
    cause the BIND daemon (named) to crash under certain
    conditions.(CVE-2015-1349)

  - A denial of service flaw was found in the way BIND
    parsed signature records for DNAME records. By sending
    a specially crafted query, a remote attacker could use
    this flaw to cause named to crash.(CVE-2016-1286)

  - A use-after-free flaw leading to denial of service was
    found in the way BIND internally handled cleanup
    operations on upstream recursion fetch contexts. A
    remote attacker could potentially use this flaw to make
    named, acting as a DNSSEC validating resolver, exit
    unexpectedly with an assertion failure via a specially
    crafted DNS request.(CVE-2017-3145)

  - A denial of service flaw was found in the way BIND
    handled query requests when using DNS64 with
    'break-dnssec yes' option. A remote attacker could use
    this flaw to make named exit unexpectedly with an
    assertion failure via a specially crafted DNS
    request.(CVE-2017-3136)

  - A flaw was found in the way BIND handled TSIG
    authentication of AXFR requests. A remote attacker,
    able to communicate with an authoritative BIND server,
    could use this flaw to view the entire contents of a
    zone by sending a specially constructed request
    packet.(CVE-2017-3142)

  - A flaw was found in the way BIND handled TSIG
    authentication for dynamic updates. A remote attacker
    able to communicate with an authoritative BIND server
    could use this flaw to manipulate the contents of a
    zone, by forging a valid TSIG or SIG(0) signature for a
    dynamic update request.(CVE-2017-3143)

  - A denial of service flaw was discovered in bind
    versions that include the 'deny-answer-aliases'
    feature. This flaw may allow a remote attacker to
    trigger an INSIST assert in named leading to
    termination of the process and a denial of service
    condition.(CVE-2018-5740)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1433
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?72d96ad2");
  script_set_attribute(attribute:"solution", value:
"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3143");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-libs-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-utils");
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

pkgs = ["bind-libs-9.9.4-61.1.h2",
        "bind-libs-lite-9.9.4-61.1.h2",
        "bind-license-9.9.4-61.1.h2",
        "bind-utils-9.9.4-61.1.h2"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind");
}
