#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3205. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(168204);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/27");

  script_cve_id(
    "CVE-2019-0053",
    "CVE-2020-8284",
    "CVE-2021-40491",
    "CVE-2022-39028"
  );

  script_name(english:"Debian DLA-3205-1 : inetutils - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3205 advisory.

  - Insufficient validation of environment variables in the telnet client supplied in Junos OS can lead to
    stack-based buffer overflows, which can be exploited to bypass veriexec restrictions on Junos OS. A stack-
    based overflow is present in the handling of environment variables when connecting via the telnet client
    to remote telnet servers. This issue only affects the telnet client  accessible from the CLI or shell 
    in Junos OS. Inbound telnet services are not affected by this issue. This issue affects: Juniper Networks
    Junos OS: 12.3 versions prior to 12.3R12-S13; 12.3X48 versions prior to 12.3X48-D80; 14.1X53 versions
    prior to 14.1X53-D130, 14.1X53-D49; 15.1 versions prior to 15.1F6-S12, 15.1R7-S4; 15.1X49 versions prior
    to 15.1X49-D170; 15.1X53 versions prior to 15.1X53-D237, 15.1X53-D496, 15.1X53-D591, 15.1X53-D69; 16.1
    versions prior to 16.1R3-S11, 16.1R7-S4; 16.2 versions prior to 16.2R2-S9; 17.1 versions prior to 17.1R3;
    17.2 versions prior to 17.2R1-S8, 17.2R2-S7, 17.2R3-S1; 17.3 versions prior to 17.3R3-S4; 17.4 versions
    prior to 17.4R1-S6, 17.4R2-S3, 17.4R3; 18.1 versions prior to 18.1R2-S4, 18.1R3-S3; 18.2 versions prior to
    18.2R1-S5, 18.2R2-S2, 18.2R3; 18.2X75 versions prior to 18.2X75-D40; 18.3 versions prior to 18.3R1-S3,
    18.3R2; 18.4 versions prior to 18.4R1-S2, 18.4R2. (CVE-2019-0053)

  - A malicious server can use the FTP PASV response to trick curl 7.73.0 and earlier into connecting back to
    a given IP address and port, and this way potentially make curl extract information about services that
    are otherwise private and not disclosed, for example doing port scanning and service banner extractions.
    (CVE-2020-8284)

  - The ftp client in GNU Inetutils before 2.2 does not validate addresses returned by PASV/LSPV responses to
    make sure they match the server address. This is similar to CVE-2020-8284 for curl. (CVE-2021-40491)

  - telnetd in GNU Inetutils through 2.3, MIT krb5-appl through 1.0.3, and derivative works has a NULL pointer
    dereference via 0xff 0xf7 or 0xff 0xf8. In a typical installation, the telnetd application would crash but
    the telnet service would remain available through inetd. However, if the telnetd application has many
    crashes within a short time interval, the telnet service would become unavailable after inetd logs a
    telnet/tcp server failing (looping), service terminated error. NOTE: MIT krb5-appl is not supported
    upstream but is shipped by a few Linux distributions. The affected code was removed from the supported MIT
    Kerberos 5 (aka krb5) product many years ago, at version 1.8. (CVE-2022-39028)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=945861");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/inetutils");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3205");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-0053");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-8284");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-40491");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39028");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/inetutils");
  script_set_attribute(attribute:"solution", value:
"Upgrade the inetutils packages.

For Debian 10 buster, these problems have been fixed in version 2");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0053");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils-ftpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils-inetd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils-ping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils-syslogd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils-talk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils-talkd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils-telnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils-telnetd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils-traceroute");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
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

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'inetutils-ftp', 'reference': '2:1.9.4-7+deb10u2'},
    {'release': '10.0', 'prefix': 'inetutils-ftpd', 'reference': '2:1.9.4-7+deb10u2'},
    {'release': '10.0', 'prefix': 'inetutils-inetd', 'reference': '2:1.9.4-7+deb10u2'},
    {'release': '10.0', 'prefix': 'inetutils-ping', 'reference': '2:1.9.4-7+deb10u2'},
    {'release': '10.0', 'prefix': 'inetutils-syslogd', 'reference': '2:1.9.4-7+deb10u2'},
    {'release': '10.0', 'prefix': 'inetutils-talk', 'reference': '2:1.9.4-7+deb10u2'},
    {'release': '10.0', 'prefix': 'inetutils-talkd', 'reference': '2:1.9.4-7+deb10u2'},
    {'release': '10.0', 'prefix': 'inetutils-telnet', 'reference': '2:1.9.4-7+deb10u2'},
    {'release': '10.0', 'prefix': 'inetutils-telnetd', 'reference': '2:1.9.4-7+deb10u2'},
    {'release': '10.0', 'prefix': 'inetutils-tools', 'reference': '2:1.9.4-7+deb10u2'},
    {'release': '10.0', 'prefix': 'inetutils-traceroute', 'reference': '2:1.9.4-7+deb10u2'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'inetutils-ftp / inetutils-ftpd / inetutils-inetd / inetutils-ping / etc');
}
