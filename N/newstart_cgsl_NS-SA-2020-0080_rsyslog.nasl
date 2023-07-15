##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0080. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143929);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/10");

  script_cve_id("CVE-2019-17041", "CVE-2019-17042");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : rsyslog Multiple Vulnerabilities (NS-SA-2020-0080)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has rsyslog packages installed that are affected
by multiple vulnerabilities:

  - An issue was discovered in Rsyslog v8.1908.0. contrib/pmcisconames/pmcisconames.c has a heap overflow in
    the parser for Cisco log messages. The parser tries to locate a log message delimiter (in this case, a
    space or a colon), but fails to account for strings that do not satisfy this constraint. If the string
    does not match, then the variable lenMsg will reach the value zero and will skip the sanity check that
    detects invalid log messages. The message will then be considered valid, and the parser will eat up the
    nonexistent colon delimiter. In doing so, it will decrement lenMsg, a signed integer, whose value was zero
    and now becomes minus one. The following step in the parser is to shift left the contents of the message.
    To do this, it will call memmove with the right pointers to the target and destination strings, but the
    lenMsg will now be interpreted as a huge value, causing a heap overflow. (CVE-2019-17042)

  - An issue was discovered in Rsyslog v8.1908.0. contrib/pmaixforwardedfrom/pmaixforwardedfrom.c has a heap
    overflow in the parser for AIX log messages. The parser tries to locate a log message delimiter (in this
    case, a space or a colon) but fails to account for strings that do not satisfy this constraint. If the
    string does not match, then the variable lenMsg will reach the value zero and will skip the sanity check
    that detects invalid log messages. The message will then be considered valid, and the parser will eat up
    the nonexistent colon delimiter. In doing so, it will decrement lenMsg, a signed integer, whose value was
    zero and now becomes minus one. The following step in the parser is to shift left the contents of the
    message. To do this, it will call memmove with the right pointers to the target and destination strings,
    but the lenMsg will now be interpreted as a huge value, causing a heap overflow. (CVE-2019-17041)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0080");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL rsyslog packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17042");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'rsyslog-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-crypto-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-debuginfo-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-doc-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-elasticsearch-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-gnutls-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-gssapi-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-kafka-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-libdbi-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-mmaudit-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-mmjsonparse-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-mmkubernetes-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-mmnormalize-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-mmsnmptrapd-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-mysql-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-pgsql-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-relp-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-snmp-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-udpspoof-8.24.0-52.el7.cgslv5.0.2.g143df60'
  ],
  'CGSL MAIN 5.04': [
    'rsyslog-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-crypto-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-debuginfo-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-doc-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-elasticsearch-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-gnutls-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-gssapi-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-kafka-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-libdbi-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-mmaudit-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-mmjsonparse-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-mmkubernetes-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-mmnormalize-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-mmsnmptrapd-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-mysql-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-pgsql-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-relp-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-snmp-8.24.0-52.el7.cgslv5.0.2.g143df60',
    'rsyslog-udpspoof-8.24.0-52.el7.cgslv5.0.2.g143df60'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rsyslog');
}
