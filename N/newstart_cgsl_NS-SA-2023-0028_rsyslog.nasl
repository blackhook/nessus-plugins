#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2023-0028. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174059);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/11");

  script_cve_id("CVE-2022-24903");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : rsyslog Vulnerability (NS-SA-2023-0028)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has rsyslog packages installed that are affected
by a vulnerability:

  - Rsyslog is a rocket-fast system for log processing. Modules for TCP syslog reception have a potential heap
    buffer overflow when octet-counted framing is used. This can result in a segfault or some other
    malfunction. As of our understanding, this vulnerability can not be used for remote code execution. But
    there may still be a slight chance for experts to do that. The bug occurs when the octet count is read.
    While there is a check for the maximum number of octets, digits are written to a heap buffer even when the
    octet count is over the maximum, This can be used to overrun the memory buffer. However, once the sequence
    of digits stop, no additional characters can be added to the buffer. In our opinion, this makes remote
    exploits impossible or at least highly complex. Octet-counted framing is one of two potential framing
    modes. It is relatively uncommon, but enabled by default on receivers. Modules `imtcp`, `imptcp`,
    `imgssapi`, and `imhttp` are used for regular syslog message reception. It is best practice not to
    directly expose them to the public. When this practice is followed, the risk is considerably lower. Module
    `imdiag` is a diagnostics module primarily intended for testbench runs. We do not expect it to be present
    on any production installation. Octet-counted framing is not very common. Usually, it needs to be
    specifically enabled at senders. If users do not need it, they can turn it off for the most important
    modules. This will mitigate the vulnerability. (CVE-2022-24903)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2023-0028");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-24903");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL rsyslog packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24903");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/11");

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
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL CORE 5.05" &&
    os_release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.05': [
    'rsyslog-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-crypto-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-debuginfo-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-doc-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-elasticsearch-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-gnutls-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-gssapi-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-kafka-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-libdbi-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-mmaudit-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-mmjsonparse-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-mmkubernetes-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-mmnormalize-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-mmsnmptrapd-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-mysql-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-pgsql-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-relp-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-snmp-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-udpspoof-8.24.0-57.el7_9.3.cgslv5_5'
  ],
  'CGSL MAIN 5.05': [
    'rsyslog-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-crypto-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-debuginfo-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-doc-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-elasticsearch-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-gnutls-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-gssapi-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-kafka-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-libdbi-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-mmaudit-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-mmjsonparse-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-mmkubernetes-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-mmnormalize-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-mmsnmptrapd-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-mysql-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-pgsql-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-relp-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-snmp-8.24.0-57.el7_9.3.cgslv5_5',
    'rsyslog-udpspoof-8.24.0-57.el7_9.3.cgslv5_5'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

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
