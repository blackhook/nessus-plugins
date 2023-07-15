#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0102. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127330);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2016-2775",
    "CVE-2017-3136",
    "CVE-2017-3137",
    "CVE-2017-3139",
    "CVE-2017-3142",
    "CVE-2017-3143"
  );

  script_name(english:"NewStart CGSL MAIN 4.05 : bind Multiple Vulnerabilities (NS-SA-2019-0102)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.05, has bind packages installed that are affected by multiple
vulnerabilities:

  - A flaw was found in the way BIND handled TSIG
    authentication for dynamic updates. A remote attacker
    able to communicate with an authoritative BIND server
    could use this flaw to manipulate the contents of a
    zone, by forging a valid TSIG or SIG(0) signature for a
    dynamic update request. (CVE-2017-3143)

  - A flaw was found in the way BIND handled TSIG
    authentication of AXFR requests. A remote attacker, able
    to communicate with an authoritative BIND server, could
    use this flaw to view the entire contents of a zone by
    sending a specially constructed request packet.
    (CVE-2017-3142)

  - A denial of service flaw was found in the way BIND
    handled DNSSEC validation. A remote attacker could use
    this flaw to make named exit unexpectedly with an
    assertion failure via a specially crafted DNS response.
    (CVE-2017-3139)

  - A denial of service flaw was found in the way BIND
    handled a query response containing CNAME or DNAME
    resource records in an unusual order. A remote attacker
    could use this flaw to make named exit unexpectedly with
    an assertion failure via a specially crafted DNS
    response. (CVE-2017-3137)

  - It was found that the lightweight resolver protocol
    implementation in BIND could enter an infinite recursion
    and crash when asked to resolve a query name which, when
    combined with a search list entry, exceeds the maximum
    allowable length. A remote attacker could use this flaw
    to crash lwresd or named when using the lwres
    statement in named.conf. (CVE-2016-2775)

  - A denial of service flaw was found in the way BIND
    handled query requests when using DNS64 with break-
    dnssec yes option. A remote attacker could use this
    flaw to make named exit unexpectedly with an assertion
    failure via a specially crafted DNS request.
    (CVE-2017-3136)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0102");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL bind packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3143");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL MAIN 4.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 4.05": [
    "bind-9.8.2-0.62.rc1.el6_9.4.4",
    "bind-chroot-9.8.2-0.62.rc1.el6_9.4.4",
    "bind-libs-9.8.2-0.62.rc1.el6_9.4.4",
    "bind-utils-9.8.2-0.62.rc1.el6_9.4.4"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
