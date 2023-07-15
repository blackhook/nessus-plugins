#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0176. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154491);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/27");

  script_cve_id("CVE-2011-3200");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : rsyslog Vulnerability (NS-SA-2021-0176)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has rsyslog packages installed that are affected
by a vulnerability:

  - Stack-based buffer overflow in the parseLegacySyslogMsg function in tools/syslogd.c in rsyslogd in rsyslog
    4.6.x before 4.6.8 and 5.2.0 through 5.8.4 might allow remote attackers to cause a denial of service
    (application exit) via a long TAG in a legacy syslog message. (CVE-2011-3200)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0176");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2011-3200");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL rsyslog packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-3200");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rsyslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rsyslog-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rsyslog-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rsyslog-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rsyslog-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rsyslog-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rsyslog-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rsyslog-kafka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rsyslog-libdbi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rsyslog-mmaudit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rsyslog-mmjsonparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rsyslog-mmkubernetes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rsyslog-mmnormalize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rsyslog-mmsnmptrapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rsyslog-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rsyslog-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rsyslog-relp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rsyslog-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rsyslog-udpspoof");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rsyslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rsyslog-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rsyslog-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rsyslog-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rsyslog-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rsyslog-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rsyslog-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rsyslog-kafka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rsyslog-libdbi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rsyslog-mmaudit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rsyslog-mmjsonparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rsyslog-mmkubernetes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rsyslog-mmnormalize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rsyslog-mmsnmptrapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rsyslog-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rsyslog-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rsyslog-relp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rsyslog-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rsyslog-udpspoof");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
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

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.05': [
    'rsyslog-8.24.0-52.el7.cgslv5_5',
    'rsyslog-crypto-8.24.0-52.el7.cgslv5_5',
    'rsyslog-debuginfo-8.24.0-52.el7.cgslv5_5',
    'rsyslog-doc-8.24.0-52.el7.cgslv5_5',
    'rsyslog-elasticsearch-8.24.0-52.el7.cgslv5_5',
    'rsyslog-gnutls-8.24.0-52.el7.cgslv5_5',
    'rsyslog-gssapi-8.24.0-52.el7.cgslv5_5',
    'rsyslog-kafka-8.24.0-52.el7.cgslv5_5',
    'rsyslog-libdbi-8.24.0-52.el7.cgslv5_5',
    'rsyslog-mmaudit-8.24.0-52.el7.cgslv5_5',
    'rsyslog-mmjsonparse-8.24.0-52.el7.cgslv5_5',
    'rsyslog-mmkubernetes-8.24.0-52.el7.cgslv5_5',
    'rsyslog-mmnormalize-8.24.0-52.el7.cgslv5_5',
    'rsyslog-mmsnmptrapd-8.24.0-52.el7.cgslv5_5',
    'rsyslog-mysql-8.24.0-52.el7.cgslv5_5',
    'rsyslog-pgsql-8.24.0-52.el7.cgslv5_5',
    'rsyslog-relp-8.24.0-52.el7.cgslv5_5',
    'rsyslog-snmp-8.24.0-52.el7.cgslv5_5',
    'rsyslog-udpspoof-8.24.0-52.el7.cgslv5_5'
  ],
  'CGSL MAIN 5.05': [
    'rsyslog-8.24.0-52.el7.cgslv5_5',
    'rsyslog-crypto-8.24.0-52.el7.cgslv5_5',
    'rsyslog-debuginfo-8.24.0-52.el7.cgslv5_5',
    'rsyslog-doc-8.24.0-52.el7.cgslv5_5',
    'rsyslog-elasticsearch-8.24.0-52.el7.cgslv5_5',
    'rsyslog-gnutls-8.24.0-52.el7.cgslv5_5',
    'rsyslog-gssapi-8.24.0-52.el7.cgslv5_5',
    'rsyslog-kafka-8.24.0-52.el7.cgslv5_5',
    'rsyslog-libdbi-8.24.0-52.el7.cgslv5_5',
    'rsyslog-mmaudit-8.24.0-52.el7.cgslv5_5',
    'rsyslog-mmjsonparse-8.24.0-52.el7.cgslv5_5',
    'rsyslog-mmkubernetes-8.24.0-52.el7.cgslv5_5',
    'rsyslog-mmnormalize-8.24.0-52.el7.cgslv5_5',
    'rsyslog-mmsnmptrapd-8.24.0-52.el7.cgslv5_5',
    'rsyslog-mysql-8.24.0-52.el7.cgslv5_5',
    'rsyslog-pgsql-8.24.0-52.el7.cgslv5_5',
    'rsyslog-relp-8.24.0-52.el7.cgslv5_5',
    'rsyslog-snmp-8.24.0-52.el7.cgslv5_5',
    'rsyslog-udpspoof-8.24.0-52.el7.cgslv5_5'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rsyslog');
}
