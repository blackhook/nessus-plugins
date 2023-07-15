#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0127. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154559);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/27");

  script_cve_id(
    "CVE-2012-4502",
    "CVE-2012-4503",
    "CVE-2014-0021",
    "CVE-2015-1821",
    "CVE-2015-1822",
    "CVE-2015-1853",
    "CVE-2016-1567"
  );

  script_name(english:"NewStart CGSL MAIN 6.02 : chrony Multiple Vulnerabilities (NS-SA-2021-0127)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has chrony packages installed that are affected by multiple
vulnerabilities:

  - Multiple integer overflows in pktlength.c in Chrony before 1.29 allow remote attackers to cause a denial
    of service (crash) via a crafted (1) REQ_SUBNETS_ACCESSED or (2) REQ_CLIENT_ACCESSES command request to
    the PKL_CommandLength function or crafted (3) RPY_SUBNETS_ACCESSED, (4) RPY_CLIENT_ACCESSES, (5)
    RPY_CLIENT_ACCESSES_BY_INDEX, or (6) RPY_MANUAL_LIST command reply to the PKL_ReplyLength function, which
    triggers an out-of-bounds read or buffer overflow. NOTE: versions 1.27 and 1.28 do not require
    authentication to exploit. (CVE-2012-4502)

  - cmdmon.c in Chrony before 1.29 allows remote attackers to obtain potentially sensitive information from
    stack memory via vectors related to (1) an invalid subnet in a RPY_SUBNETS_ACCESSED command to the
    handle_subnets_accessed function or (2) a RPY_CLIENT_ACCESSES command to the handle_client_accesses
    function when client logging is disabled, which causes uninitialized data to be included in a reply.
    (CVE-2012-4503)

  - Chrony before 1.29.1 has traffic amplification in cmdmon protocol (CVE-2014-0021)

  - Heap-based buffer overflow in chrony before 1.31.1 allows remote authenticated users to cause a denial of
    service (chronyd crash) or possibly execute arbitrary code by configuring the (1) NTP or (2) cmdmon access
    with a subnet size that is indivisible by four and an address with a nonzero bit in the subnet remainder.
    (CVE-2015-1821)

  - chrony before 1.31.1 does not initialize the last next pointer when saving unacknowledged replies to
    command requests, which allows remote authenticated users to cause a denial of service (uninitialized
    pointer dereference and daemon crash) or possibly execute arbitrary code via a large number of command
    requests. (CVE-2015-1822)

  - chrony before 1.31.1 does not properly protect state variables in authenticated symmetric NTP
    associations, which allows remote attackers with knowledge of NTP peering to cause a denial of service
    (inability to synchronize) via random timestamps in crafted NTP data packets. (CVE-2015-1853)

  - chrony before 1.31.2 and 2.x before 2.2.1 do not verify peer associations of symmetric keys when
    authenticating packets, which might allow remote attackers to conduct impersonation attacks via an
    arbitrary trusted key, aka a skeleton key. (CVE-2016-1567)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0127");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2012-4502");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2012-4503");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2014-0021");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2015-1821");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2015-1822");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2015-1853");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2016-1567");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL chrony packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1567");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:chrony");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:chrony-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:chrony-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'chrony-3.5-1.el8.cgslv6_2.0.1.g6211dc8',
    'chrony-debuginfo-3.5-1.el8.cgslv6_2.0.1.g6211dc8',
    'chrony-debugsource-3.5-1.el8.cgslv6_2.0.1.g6211dc8'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'chrony');
}
