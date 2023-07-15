#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0098. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154478);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-14834",
    "CVE-2020-25684",
    "CVE-2020-25685",
    "CVE-2020-25686"
  );
  script_xref(name:"IAVA", value:"2020-A-0194-S");
  script_xref(name:"IAVA", value:"2021-A-0041");
  script_xref(name:"CEA-ID", value:"CEA-2021-0003");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : dnsmasq Multiple Vulnerabilities (NS-SA-2021-0098)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has dnsmasq packages installed that are affected
by multiple vulnerabilities:

  - A vulnerability was found in dnsmasq before version 2.81, where the memory leak allows remote attackers to
    cause a denial of service (memory consumption) via vectors involving DHCP response creation.
    (CVE-2019-14834)

  - A flaw was found in dnsmasq before version 2.83. When getting a reply from a forwarded query, dnsmasq
    checks in the forward.c:reply_query() if the reply destination address/port is used by the pending
    forwarded queries. However, it does not use the address/port to retrieve the exact forwarded query,
    substantially reducing the number of attempts an attacker on the network would have to perform to forge a
    reply and get it accepted by dnsmasq. This issue contrasts with RFC5452, which specifies a query's
    attributes that all must be used to match a reply. This flaw allows an attacker to perform a DNS Cache
    Poisoning attack. If chained with CVE-2020-25685 or CVE-2020-25686, the attack complexity of a successful
    attack is reduced. The highest threat from this vulnerability is to data integrity. (CVE-2020-25684)

  - A flaw was found in dnsmasq before version 2.83. When getting a reply from a forwarded query, dnsmasq
    checks in forward.c:reply_query(), which is the forwarded query that matches the reply, by only using a
    weak hash of the query name. Due to the weak hash (CRC32 when dnsmasq is compiled without DNSSEC, SHA-1
    when it is) this flaw allows an off-path attacker to find several different domains all having the same
    hash, substantially reducing the number of attempts they would have to perform to forge a reply and get it
    accepted by dnsmasq. This is in contrast with RFC5452, which specifies that the query name is one of the
    attributes of a query that must be used to match a reply. This flaw could be abused to perform a DNS Cache
    Poisoning attack. If chained with CVE-2020-25684 the attack complexity of a successful attack is reduced.
    The highest threat from this vulnerability is to data integrity. (CVE-2020-25685)

  - A flaw was found in dnsmasq before version 2.83. When receiving a query, dnsmasq does not check for an
    existing pending request for the same name and forwards a new request. By default, a maximum of 150
    pending queries can be sent to upstream servers, so there can be at most 150 queries for the same name.
    This flaw allows an off-path attacker on the network to substantially reduce the number of attempts that
    it would have to perform to forge a reply and have it accepted by dnsmasq. This issue is mentioned in the
    Birthday Attacks section of RFC5452. If chained with CVE-2020-25684, the attack complexity of a
    successful attack is reduced. The highest threat from this vulnerability is to data integrity.
    (CVE-2020-25686)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0098");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-14834");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-25684");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-25685");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-25686");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL dnsmasq packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25686");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:dnsmasq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:dnsmasq-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:dnsmasq-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:dnsmasq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:dnsmasq-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:dnsmasq-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.04': [
    'dnsmasq-2.76-16.el7_9.1',
    'dnsmasq-debuginfo-2.76-16.el7_9.1',
    'dnsmasq-utils-2.76-16.el7_9.1'
  ],
  'CGSL MAIN 5.04': [
    'dnsmasq-2.76-16.el7_9.1',
    'dnsmasq-debuginfo-2.76-16.el7_9.1',
    'dnsmasq-utils-2.76-16.el7_9.1'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dnsmasq');
}
