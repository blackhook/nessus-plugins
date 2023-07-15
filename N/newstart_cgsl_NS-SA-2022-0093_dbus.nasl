#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0093. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167488);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/16");

  script_cve_id(
    "CVE-2006-6107",
    "CVE-2008-0595",
    "CVE-2009-1189",
    "CVE-2012-3524",
    "CVE-2013-2168",
    "CVE-2014-3477",
    "CVE-2014-3533",
    "CVE-2014-3635",
    "CVE-2014-3636",
    "CVE-2014-3637",
    "CVE-2014-3638",
    "CVE-2014-3639",
    "CVE-2014-7824",
    "CVE-2015-0245",
    "CVE-2020-12049"
  );

  script_name(english:"NewStart CGSL MAIN 6.02 : dbus Multiple Vulnerabilities (NS-SA-2022-0093)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has dbus packages installed that are affected by multiple
vulnerabilities:

  - Unspecified vulnerability in the match_rule_equal function in bus/signals.c in D-Bus before 1.0.2 allows
    local applications to remove match rules for other applications and cause a denial of service (lost
    process messages). (CVE-2006-6107)

  - dbus-daemon in D-Bus before 1.0.3, and 1.1.x before 1.1.20, recognizes send_interface attributes in allow
    directives in the security policy only for fully qualified method calls, which allows local users to
    bypass intended access restrictions via a method call with a NULL interface. (CVE-2008-0595)

  - The _dbus_validate_signature_with_reason function (dbus-marshal-validate.c) in D-Bus (aka DBus) before
    1.2.14 uses incorrect logic to validate a basic type, which allows remote attackers to spoof a signature
    via a crafted key. NOTE: this is due to an incorrect fix for CVE-2008-3834. (CVE-2009-1189)

  - libdbus 1.5.x and earlier, when used in setuid or other privileged programs in X.org and possibly other
    products, allows local users to gain privileges and execute arbitrary code via the DBUS_SYSTEM_BUS_ADDRESS
    environment variable. NOTE: libdbus maintainers state that this is a vulnerability in the applications
    that do not cleanse environment variables, not in libdbus itself: we do not support use of libdbus in
    setuid binaries that do not sanitize their environment before their first call into libdbus.
    (CVE-2012-3524)

  - The _dbus_printf_string_upper_bound function in dbus/dbus-sysdeps-unix.c in D-Bus (aka DBus) 1.4.x before
    1.4.26, 1.6.x before 1.6.12, and 1.7.x before 1.7.4 allows local users to cause a denial of service
    (service crash) via a crafted message. (CVE-2013-2168)

  - The dbus-daemon in D-Bus 1.2.x through 1.4.x, 1.6.x before 1.6.20, and 1.8.x before 1.8.4, sends an
    AccessDenied error to the service instead of a client when the client is prohibited from accessing the
    service, which allows local users to cause a denial of service (initialization failure and exit) or
    possibly conduct a side-channel attack via a D-Bus message to an inactive service. (CVE-2014-3477)

  - dbus 1.3.0 before 1.6.22 and 1.8.x before 1.8.6 allows local users to cause a denial of service
    (disconnect) via a certain sequence of crafted messages that cause the dbus-daemon to forward a message
    containing an invalid file descriptor. (CVE-2014-3533)

  - Off-by-one error in D-Bus 1.3.0 through 1.6.x before 1.6.24 and 1.8.x before 1.8.8, when running on a
    64-bit system and the max_message_unix_fds limit is set to an odd number, allows local users to cause a
    denial of service (dbus-daemon crash) or possibly execute arbitrary code by sending one more file
    descriptor than the limit, which triggers a heap-based buffer overflow or an assertion failure.
    (CVE-2014-3635)

  - D-Bus 1.3.0 through 1.6.x before 1.6.24 and 1.8.x before 1.8.8 allows local users to (1) cause a denial of
    service (prevention of new connections and connection drop) by queuing the maximum number of file
    descriptors or (2) cause a denial of service (disconnect) via multiple messages that combine to have more
    than the allowed number of file descriptors for a single sendmsg call. (CVE-2014-3636)

  - D-Bus 1.3.0 through 1.6.x before 1.6.24 and 1.8.x before 1.8.8 does not properly close connections for
    processes that have terminated, which allows local users to cause a denial of service via a D-bus message
    containing a D-Bus connection file descriptor. (CVE-2014-3637)

  - The bus_connections_check_reply function in config-parser.c in D-Bus before 1.6.24 and 1.8.x before 1.8.8
    allows local users to cause a denial of service (CPU consumption) via a large number of method calls.
    (CVE-2014-3638)

  - The dbus-daemon in D-Bus before 1.6.24 and 1.8.x before 1.8.8 does not properly close old connections,
    which allows local users to cause a denial of service (incomplete connection consumption and prevention of
    new connections) via a large number of incomplete connections. (CVE-2014-3639)

  - D-Bus 1.3.0 through 1.6.x before 1.6.26, 1.8.x before 1.8.10, and 1.9.x before 1.9.2 allows local users to
    cause a denial of service (prevention of new connections and connection drop) by queuing the maximum
    number of file descriptors. NOTE: this vulnerability exists because of an incomplete fix for
    CVE-2014-3636.1. (CVE-2014-7824)

  - D-Bus 1.4.x through 1.6.x before 1.6.30, 1.8.x before 1.8.16, and 1.9.x before 1.9.10 does not validate
    the source of ActivationFailure signals, which allows local users to cause a denial of service (activation
    failure error returned) by leveraging a race condition involving sending an ActivationFailure signal
    before systemd responds. (CVE-2015-0245)

  - An issue was discovered in dbus >= 1.3.0 before 1.12.18. The DBusServer in libdbus, as used in dbus-
    daemon, leaks file descriptors when a message exceeds the per-message file descriptor limit. A local
    attacker with access to the D-Bus system bus or another system service's private AF_UNIX socket could use
    this to make the system service reach its file descriptor limit, denying service to subsequent D-Bus
    clients. (CVE-2020-12049)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0093");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2006-6107");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2008-0595");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2009-1189");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2012-3524");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2013-2168");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2014-3477");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2014-3533");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2014-3635");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2014-3636");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2014-3637");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2014-3638");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2014-3639");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2014-7824");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2015-0245");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-12049");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL dbus packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-3524");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-12049");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:dbus-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:dbus-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:dbus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:dbus-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:dbus-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:dbus-x11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'dbus-1.12.8-10.el8_2.cgslv6_2.2.g1f9b92c',
    'dbus-common-1.12.8-10.el8_2.cgslv6_2.2.g1f9b92c',
    'dbus-daemon-1.12.8-10.el8_2.cgslv6_2.2.g1f9b92c',
    'dbus-devel-1.12.8-10.el8_2.cgslv6_2.2.g1f9b92c',
    'dbus-libs-1.12.8-10.el8_2.cgslv6_2.2.g1f9b92c',
    'dbus-tools-1.12.8-10.el8_2.cgslv6_2.2.g1f9b92c',
    'dbus-x11-1.12.8-10.el8_2.cgslv6_2.2.g1f9b92c'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dbus');
}
