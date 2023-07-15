#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2717. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152006);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/20");

  script_cve_id("CVE-2021-32761");

  script_name(english:"Debian DLA-2717-1 : redis - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by a vulnerability as referenced in the dla-2717
advisory.

  - Redis is an in-memory database that persists on disk. A vulnerability involving out-of-bounds read and
    integer overflow to buffer overflow exists starting with version 2.2 and prior to versions 5.0.13, 6.0.15,
    and 6.2.5. On 32-bit systems, Redis `*BIT*` command are vulnerable to integer overflow that can
    potentially be exploited to corrupt the heap, leak arbitrary heap contents or trigger remote code
    execution. The vulnerability involves changing the default `proto-max-bulk-len` configuration parameter to
    a very large value and constructing specially crafted commands bit commands. This problem only affects
    Redis on 32-bit platforms, or compiled as a 32-bit binary. Redis versions 5.0.`3m 6.0.15, and 6.2.5
    contain patches for this issue. An additional workaround to mitigate the problem without patching the
    `redis-server` executable is to prevent users from modifying the `proto-max-bulk-len` configuration
    parameter. This can be done using ACL to restrict unprivileged users from using the CONFIG SET command.
    (CVE-2021-32761)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2717");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32761");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/redis");
  script_set_attribute(attribute:"solution", value:
"Upgrade the redis packages.

For Debian 9 Stretch, these problems have been fixed in version 3");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32761");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:redis-sentinel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:redis-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:redis-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
release = chomp(release);
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

pkgs = [
    {'release': '9.0', 'prefix': 'redis-sentinel', 'reference': '3:3.2.6-3+deb9u5'},
    {'release': '9.0', 'prefix': 'redis-server', 'reference': '3:3.2.6-3+deb9u5'},
    {'release': '9.0', 'prefix': 'redis-tools', 'reference': '3:3.2.6-3+deb9u5'}
];

flag = 0;
foreach package_array ( pkgs ) {
  release = NULL;
  prefix = NULL;
  reference = NULL;
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
  tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'redis-sentinel / redis-server / redis-tools');
}
