##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4737-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148006);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2020-8625");
  script_xref(name:"USN", value:"4737-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 : Bind vulnerability (USN-4737-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 host has packages installed that are affected by a
vulnerability as referenced in the USN-4737-1 advisory.

  - BIND servers are vulnerable if they are running an affected version and are configured to use GSS-TSIG
    features. In a configuration which uses BIND's default settings the vulnerable code path is not exposed,
    but a server can be rendered vulnerable by explicitly setting valid values for the tkey-gssapi-keytab or
    tkey-gssapi-credentialconfiguration options. Although the default configuration is not vulnerable, GSS-
    TSIG is frequently used in networks where BIND is integrated with Samba, as well as in mixed-server
    environments that combine BIND servers with Active Directory domain controllers. The most likely outcome
    of a successful exploitation of the vulnerability is a crash of the named process. However, remote code
    execution, while unproven, is theoretically possible. Affects: BIND 9.5.0 -> 9.11.27, 9.12.0 -> 9.16.11,
    and versions BIND 9.11.3-S1 -> 9.11.27-S1 and 9.16.8-S1 -> 9.16.11-S1 of BIND Supported Preview Edition.
    Also release versions 9.17.0 -> 9.17.1 of the BIND 9.17 development branch (CVE-2020-8625)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4737-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8625");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9-dnsutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dnsutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libbind-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libbind-export-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libbind9-140");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libbind9-160");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdns-export1100");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdns-export1100-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdns-export162");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdns-export162-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdns1100");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdns162");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libirs-export141");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libirs-export141-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libirs-export160");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libirs-export160-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libirs141");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libirs160");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisc-export160");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisc-export160-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisc-export169");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisc-export169-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisc160");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisc169");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccc-export140");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccc-export140-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccc-export160");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccc-export160-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccc140");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccc160");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccfg-export140");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccfg-export140-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccfg-export160");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccfg-export160-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccfg140");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccfg160");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblwres141");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblwres160");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lwresd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(16\.04|18\.04|20\.04|20\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 20.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'bind9', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.18'},
    {'osver': '16.04', 'pkgname': 'bind9-host', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.18'},
    {'osver': '16.04', 'pkgname': 'bind9utils', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.18'},
    {'osver': '16.04', 'pkgname': 'dnsutils', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.18'},
    {'osver': '16.04', 'pkgname': 'host', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.18'},
    {'osver': '16.04', 'pkgname': 'libbind-dev', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.18'},
    {'osver': '16.04', 'pkgname': 'libbind-export-dev', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.18'},
    {'osver': '16.04', 'pkgname': 'libbind9-140', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.18'},
    {'osver': '16.04', 'pkgname': 'libdns-export162', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.18'},
    {'osver': '16.04', 'pkgname': 'libdns-export162-udeb', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.18'},
    {'osver': '16.04', 'pkgname': 'libdns162', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.18'},
    {'osver': '16.04', 'pkgname': 'libirs-export141', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.18'},
    {'osver': '16.04', 'pkgname': 'libirs-export141-udeb', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.18'},
    {'osver': '16.04', 'pkgname': 'libirs141', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.18'},
    {'osver': '16.04', 'pkgname': 'libisc-export160', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.18'},
    {'osver': '16.04', 'pkgname': 'libisc-export160-udeb', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.18'},
    {'osver': '16.04', 'pkgname': 'libisc160', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.18'},
    {'osver': '16.04', 'pkgname': 'libisccc-export140', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.18'},
    {'osver': '16.04', 'pkgname': 'libisccc-export140-udeb', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.18'},
    {'osver': '16.04', 'pkgname': 'libisccc140', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.18'},
    {'osver': '16.04', 'pkgname': 'libisccfg-export140', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.18'},
    {'osver': '16.04', 'pkgname': 'libisccfg-export140-udeb', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.18'},
    {'osver': '16.04', 'pkgname': 'libisccfg140', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.18'},
    {'osver': '16.04', 'pkgname': 'liblwres141', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.18'},
    {'osver': '16.04', 'pkgname': 'lwresd', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.18'},
    {'osver': '18.04', 'pkgname': 'bind9', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.14'},
    {'osver': '18.04', 'pkgname': 'bind9-host', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.14'},
    {'osver': '18.04', 'pkgname': 'bind9utils', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.14'},
    {'osver': '18.04', 'pkgname': 'dnsutils', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.14'},
    {'osver': '18.04', 'pkgname': 'libbind-dev', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.14'},
    {'osver': '18.04', 'pkgname': 'libbind-export-dev', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.14'},
    {'osver': '18.04', 'pkgname': 'libbind9-160', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.14'},
    {'osver': '18.04', 'pkgname': 'libdns-export1100', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.14'},
    {'osver': '18.04', 'pkgname': 'libdns-export1100-udeb', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.14'},
    {'osver': '18.04', 'pkgname': 'libdns1100', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.14'},
    {'osver': '18.04', 'pkgname': 'libirs-export160', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.14'},
    {'osver': '18.04', 'pkgname': 'libirs-export160-udeb', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.14'},
    {'osver': '18.04', 'pkgname': 'libirs160', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.14'},
    {'osver': '18.04', 'pkgname': 'libisc-export169', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.14'},
    {'osver': '18.04', 'pkgname': 'libisc-export169-udeb', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.14'},
    {'osver': '18.04', 'pkgname': 'libisc169', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.14'},
    {'osver': '18.04', 'pkgname': 'libisccc-export160', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.14'},
    {'osver': '18.04', 'pkgname': 'libisccc-export160-udeb', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.14'},
    {'osver': '18.04', 'pkgname': 'libisccc160', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.14'},
    {'osver': '18.04', 'pkgname': 'libisccfg-export160', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.14'},
    {'osver': '18.04', 'pkgname': 'libisccfg-export160-udeb', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.14'},
    {'osver': '18.04', 'pkgname': 'libisccfg160', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.14'},
    {'osver': '18.04', 'pkgname': 'liblwres160', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.14'},
    {'osver': '20.04', 'pkgname': 'bind9', 'pkgver': '1:9.16.1-0ubuntu2.6'},
    {'osver': '20.04', 'pkgname': 'bind9-dnsutils', 'pkgver': '1:9.16.1-0ubuntu2.6'},
    {'osver': '20.04', 'pkgname': 'bind9-host', 'pkgver': '1:9.16.1-0ubuntu2.6'},
    {'osver': '20.04', 'pkgname': 'bind9-libs', 'pkgver': '1:9.16.1-0ubuntu2.6'},
    {'osver': '20.04', 'pkgname': 'bind9-utils', 'pkgver': '1:9.16.1-0ubuntu2.6'},
    {'osver': '20.04', 'pkgname': 'bind9utils', 'pkgver': '1:9.16.1-0ubuntu2.6'},
    {'osver': '20.04', 'pkgname': 'dnsutils', 'pkgver': '1:9.16.1-0ubuntu2.6'},
    {'osver': '20.10', 'pkgname': 'bind9', 'pkgver': '1:9.16.6-3ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'bind9-dev', 'pkgver': '1:9.16.6-3ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'bind9-dnsutils', 'pkgver': '1:9.16.6-3ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'bind9-host', 'pkgver': '1:9.16.6-3ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'bind9-libs', 'pkgver': '1:9.16.6-3ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'bind9-utils', 'pkgver': '1:9.16.6-3ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'bind9utils', 'pkgver': '1:9.16.6-3ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'dnsutils', 'pkgver': '1:9.16.6-3ubuntu1.1'}
];

flag = 0;
foreach package_array ( pkgs ) {
  osver = NULL;
  pkgname = NULL;
  pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind9 / bind9-dev / bind9-dnsutils / bind9-host / bind9-libs / etc');
}