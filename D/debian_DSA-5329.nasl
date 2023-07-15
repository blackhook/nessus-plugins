#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5329. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(170726);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/30");

  script_cve_id("CVE-2022-3094", "CVE-2022-3736", "CVE-2022-3924");
  script_xref(name:"IAVA", value:"2023-A-0058-S");

  script_name(english:"Debian DSA-5329-1 : bind9 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5329 advisory.

  - Sending a flood of dynamic DNS updates may cause `named` to allocate large amounts of memory. This, in
    turn, may cause `named` to exit due to a lack of free memory. We are not aware of any cases where this has
    been exploited. Memory is allocated prior to the checking of access permissions (ACLs) and is retained
    during the processing of a dynamic update from a client whose access credentials are accepted. Memory
    allocated to clients that are not permitted to send updates is released immediately upon rejection. The
    scope of this vulnerability is limited therefore to trusted clients who are permitted to make dynamic zone
    changes. If a dynamic update is REFUSED, memory will be released again very quickly. Therefore it is only
    likely to be possible to degrade or stop `named` by sending a flood of unaccepted dynamic updates
    comparable in magnitude to a query flood intended to achieve the same detrimental outcome. BIND 9.11 and
    earlier branches are also affected, but through exhaustion of internal resources rather than memory
    constraints. This may reduce performance but should not be a significant problem for most servers.
    Therefore we don't intend to address this for BIND versions prior to BIND 9.16. This issue affects BIND 9
    versions 9.16.0 through 9.16.36, 9.18.0 through 9.18.10, 9.19.0 through 9.19.8, and 9.16.8-S1 through
    9.16.36-S1. (CVE-2022-3094)

  - BIND 9 resolver can crash when stale cache and stale answers are enabled, option `stale-answer-client-
    timeout` is set to a positive integer, and the resolver receives an RRSIG query. This issue affects BIND 9
    versions 9.16.12 through 9.16.36, 9.18.0 through 9.18.10, 9.19.0 through 9.19.8, and 9.16.12-S1 through
    9.16.36-S1. (CVE-2022-3736)

  - This issue can affect BIND 9 resolvers with `stale-answer-enable yes;` that also make use of the option
    `stale-answer-client-timeout`, configured with a value greater than zero. If the resolver receives many
    queries that require recursion, there will be a corresponding increase in the number of clients that are
    waiting for recursion to complete. If there are sufficient clients already waiting when a new client query
    is received so that it is necessary to SERVFAIL the longest waiting client (see BIND 9 ARM `recursive-
    clients` limit and soft quota), then it is possible for a race to occur between providing a stale answer
    to this older client and sending an early timeout SERVFAIL, which may cause an assertion failure. This
    issue affects BIND 9 versions 9.16.12 through 9.16.36, 9.18.0 through 9.18.10, 9.19.0 through 9.19.8, and
    9.16.12-S1 through 9.16.36-S1. (CVE-2022-3924)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/bind9");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5329");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3094");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3736");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3924");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/bind9");
  script_set_attribute(attribute:"solution", value:
"Upgrade the bind9 packages.

For the stable distribution (bullseye), these problems have been fixed in version 1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3736");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9-dnsutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dnsutils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'bind9', 'reference': '1:9.16.37-1~deb11u1'},
    {'release': '11.0', 'prefix': 'bind9-dev', 'reference': '1:9.16.37-1~deb11u1'},
    {'release': '11.0', 'prefix': 'bind9-dnsutils', 'reference': '1:9.16.37-1~deb11u1'},
    {'release': '11.0', 'prefix': 'bind9-doc', 'reference': '1:9.16.37-1~deb11u1'},
    {'release': '11.0', 'prefix': 'bind9-host', 'reference': '1:9.16.37-1~deb11u1'},
    {'release': '11.0', 'prefix': 'bind9-libs', 'reference': '1:9.16.37-1~deb11u1'},
    {'release': '11.0', 'prefix': 'bind9-utils', 'reference': '1:9.16.37-1~deb11u1'},
    {'release': '11.0', 'prefix': 'bind9utils', 'reference': '1:9.16.37-1~deb11u1'},
    {'release': '11.0', 'prefix': 'dnsutils', 'reference': '1:9.16.37-1~deb11u1'}
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
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind9 / bind9-dev / bind9-dnsutils / bind9-doc / bind9-host / etc');
}
