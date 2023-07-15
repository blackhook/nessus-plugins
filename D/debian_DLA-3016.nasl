#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3016. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(161461);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/24");

  script_cve_id("CVE-2018-16881", "CVE-2022-24903");

  script_name(english:"Debian DLA-3016-1 : rsyslog - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3016 advisory.

  - A denial of service vulnerability was found in rsyslog in the imptcp module. An attacker could send a
    specially crafted message to the imptcp socket, which would cause rsyslog to crash. Versions before 8.27.0
    are vulnerable. (CVE-2018-16881)

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

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1010619");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/rsyslog");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3016");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-16881");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24903");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/rsyslog");
  script_set_attribute(attribute:"solution", value:
"Upgrade the rsyslog packages.

For Debian 9 stretch, these problems have been fixed in version 8.24.0-1+deb9u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24903");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rsyslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rsyslog-czmq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rsyslog-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rsyslog-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rsyslog-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rsyslog-hiredis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rsyslog-kafka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rsyslog-mongodb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rsyslog-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rsyslog-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rsyslog-relp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'rsyslog', 'reference': '8.24.0-1+deb9u2'},
    {'release': '9.0', 'prefix': 'rsyslog-czmq', 'reference': '8.24.0-1+deb9u2'},
    {'release': '9.0', 'prefix': 'rsyslog-elasticsearch', 'reference': '8.24.0-1+deb9u2'},
    {'release': '9.0', 'prefix': 'rsyslog-gnutls', 'reference': '8.24.0-1+deb9u2'},
    {'release': '9.0', 'prefix': 'rsyslog-gssapi', 'reference': '8.24.0-1+deb9u2'},
    {'release': '9.0', 'prefix': 'rsyslog-hiredis', 'reference': '8.24.0-1+deb9u2'},
    {'release': '9.0', 'prefix': 'rsyslog-kafka', 'reference': '8.24.0-1+deb9u2'},
    {'release': '9.0', 'prefix': 'rsyslog-mongodb', 'reference': '8.24.0-1+deb9u2'},
    {'release': '9.0', 'prefix': 'rsyslog-mysql', 'reference': '8.24.0-1+deb9u2'},
    {'release': '9.0', 'prefix': 'rsyslog-pgsql', 'reference': '8.24.0-1+deb9u2'},
    {'release': '9.0', 'prefix': 'rsyslog-relp', 'reference': '8.24.0-1+deb9u2'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rsyslog / rsyslog-czmq / rsyslog-elasticsearch / rsyslog-gnutls / etc');
}
