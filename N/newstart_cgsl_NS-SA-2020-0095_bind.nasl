##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0095. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144003);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/10");

  script_cve_id("CVE-2018-5745", "CVE-2019-6465", "CVE-2019-6477");
  script_bugtraq_id(107140, 107142);

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : bind Multiple Vulnerabilities (NS-SA-2020-0095)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has bind packages installed that are affected by
multiple vulnerabilities:

  - managed-keys is a feature which allows a BIND resolver to automatically maintain the keys used by trust
    anchors which operators configure for use in DNSSEC validation. Due to an error in the managed-keys
    feature it is possible for a BIND server which uses managed-keys to exit due to an assertion failure if,
    during key rollover, a trust anchor's keys are replaced with keys which use an unsupported algorithm.
    Versions affected: BIND 9.9.0 -> 9.10.8-P1, 9.11.0 -> 9.11.5-P1, 9.12.0 -> 9.12.3-P1, and versions
    9.9.3-S1 -> 9.11.5-S3 of BIND 9 Supported Preview Edition. Versions 9.13.0 -> 9.13.6 of the 9.13
    development branch are also affected. Versions prior to BIND 9.9.0 have not been evaluated for
    vulnerability to CVE-2018-5745. (CVE-2018-5745)

  - Controls for zone transfers may not be properly applied to Dynamically Loadable Zones (DLZs) if the zones
    are writable Versions affected: BIND 9.9.0 -> 9.10.8-P1, 9.11.0 -> 9.11.5-P2, 9.12.0 -> 9.12.3-P2, and
    versions 9.9.3-S1 -> 9.11.5-S3 of BIND 9 Supported Preview Edition. Versions 9.13.0 -> 9.13.6 of the 9.13
    development branch are also affected. Versions prior to BIND 9.9.0 have not been evaluated for
    vulnerability to CVE-2019-6465. (CVE-2019-6465)

  - With pipelining enabled each incoming query on a TCP connection requires a similar resource allocation to
    a query received via UDP or via TCP without pipelining enabled. A client using a TCP-pipelined connection
    to a server could consume more resources than the server has been provisioned to handle. When a TCP
    connection with a large number of pipelined queries is closed, the load on the server releasing these
    multiple resources can cause it to become unresponsive, even for queries that can be answered
    authoritatively or from cache. (This is most likely to be perceived as an intermittent server problem).
    (CVE-2019-6477)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0095");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL bind packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6465");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/21");
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

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL CORE 5.05': [
    'bind-9.11.4-16.P2.el7_8.2',
    'bind-chroot-9.11.4-16.P2.el7_8.2',
    'bind-debuginfo-9.11.4-16.P2.el7_8.2',
    'bind-devel-9.11.4-16.P2.el7_8.2',
    'bind-export-devel-9.11.4-16.P2.el7_8.2',
    'bind-export-libs-9.11.4-16.P2.el7_8.2',
    'bind-libs-9.11.4-16.P2.el7_8.2',
    'bind-libs-lite-9.11.4-16.P2.el7_8.2',
    'bind-license-9.11.4-16.P2.el7_8.2',
    'bind-lite-devel-9.11.4-16.P2.el7_8.2',
    'bind-pkcs11-9.11.4-16.P2.el7_8.2',
    'bind-pkcs11-devel-9.11.4-16.P2.el7_8.2',
    'bind-pkcs11-libs-9.11.4-16.P2.el7_8.2',
    'bind-pkcs11-utils-9.11.4-16.P2.el7_8.2',
    'bind-sdb-9.11.4-16.P2.el7_8.2',
    'bind-sdb-chroot-9.11.4-16.P2.el7_8.2',
    'bind-utils-9.11.4-16.P2.el7_8.2'
  ],
  'CGSL MAIN 5.05': [
    'bind-9.11.4-16.P2.el7_8.2',
    'bind-chroot-9.11.4-16.P2.el7_8.2',
    'bind-debuginfo-9.11.4-16.P2.el7_8.2',
    'bind-devel-9.11.4-16.P2.el7_8.2',
    'bind-export-devel-9.11.4-16.P2.el7_8.2',
    'bind-export-libs-9.11.4-16.P2.el7_8.2',
    'bind-libs-9.11.4-16.P2.el7_8.2',
    'bind-libs-lite-9.11.4-16.P2.el7_8.2',
    'bind-license-9.11.4-16.P2.el7_8.2',
    'bind-lite-devel-9.11.4-16.P2.el7_8.2',
    'bind-pkcs11-9.11.4-16.P2.el7_8.2',
    'bind-pkcs11-devel-9.11.4-16.P2.el7_8.2',
    'bind-pkcs11-libs-9.11.4-16.P2.el7_8.2',
    'bind-pkcs11-utils-9.11.4-16.P2.el7_8.2',
    'bind-sdb-9.11.4-16.P2.el7_8.2',
    'bind-sdb-chroot-9.11.4-16.P2.el7_8.2',
    'bind-utils-9.11.4-16.P2.el7_8.2'
  ]
};
pkg_list = pkgs[release];

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind');
}
