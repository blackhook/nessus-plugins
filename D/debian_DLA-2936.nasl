#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2936. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159090);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id(
    "CVE-2018-8098",
    "CVE-2018-8099",
    "CVE-2018-10887",
    "CVE-2018-10888",
    "CVE-2018-15501",
    "CVE-2019-1352",
    "CVE-2019-1353",
    "CVE-2020-12278",
    "CVE-2020-12279"
  );
  script_xref(name:"IAVA", value:"2019-A-0454-S");

  script_name(english:"Debian DLA-2936-1 : libgit2 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2936 advisory.

  - A flaw was found in libgit2 before version 0.27.3. It has been discovered that an unexpected sign
    extension in git_delta_apply function in delta.c file may lead to an integer overflow which in turn leads
    to an out of bound read, allowing to read before the base object. An attacker may use this flaw to leak
    memory addresses or cause a Denial of Service. (CVE-2018-10887)

  - A flaw was found in libgit2 before version 0.27.3. A missing check in git_delta_apply function in delta.c
    file, may lead to an out-of-bound read while reading a binary delta file. An attacker may use this flaw to
    cause a Denial of Service. (CVE-2018-10888)

  - In ng_pkt in transports/smart_pkt.c in libgit2 before 0.26.6 and 0.27.x before 0.27.4, a remote attacker
    can send a crafted smart-protocol ng packet that lacks a '\0' byte to trigger an out-of-bounds read that
    leads to DoS. (CVE-2018-15501)

  - Integer overflow in the index.c:read_entry() function while decompressing a compressed prefix length in
    libgit2 before v0.26.2 allows an attacker to cause a denial of service (out-of-bounds read) via a crafted
    repository index file. (CVE-2018-8098)

  - Incorrect returning of an error code in the index.c:read_entry() function leads to a double free in
    libgit2 before v0.26.2, which allows an attacker to cause a denial of service via a crafted repository
    index file. (CVE-2018-8099)

  - A remote code execution vulnerability exists when Git for Visual Studio improperly sanitizes input, aka
    'Git for Visual Studio Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2019-1349,
    CVE-2019-1350, CVE-2019-1354, CVE-2019-1387. (CVE-2019-1352)

  - An issue was found in Git before v2.24.1, v2.23.1, v2.22.2, v2.21.1, v2.20.2, v2.19.3, v2.18.2, v2.17.3,
    v2.16.6, v2.15.4, and v2.14.6. When running Git in the Windows Subsystem for Linux (also known as WSL)
    while accessing a working directory on a regular Windows drive, none of the NTFS protections were active.
    (CVE-2019-1353)

  - An issue was discovered in libgit2 before 0.28.4 and 0.9x before 0.99.0. path.c mishandles equivalent
    filenames that exist because of NTFS Alternate Data Streams. This may allow remote code execution when
    cloning a repository. This issue is similar to CVE-2019-1352. (CVE-2020-12278)

  - An issue was discovered in libgit2 before 0.28.4 and 0.9x before 0.99.0. checkout.c mishandles equivalent
    filenames that exist because of NTFS short names. This may allow remote code execution when cloning a
    repository. This issue is similar to CVE-2019-1353. (CVE-2020-12279)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=892961");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/libgit2");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2936");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-10887");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-10888");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-15501");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-8098");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-8099");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-1352");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-1353");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-12278");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-12279");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/libgit2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libgit2 packages.

For Debian 9 stretch, these problems have been fixed in version 0.25.1+really0.24.6-1+deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1352");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-12279");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgit2-24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgit2-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
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
    {'release': '9.0', 'prefix': 'libgit2-24', 'reference': '0.25.1+really0.24.6-1+deb9u1'},
    {'release': '9.0', 'prefix': 'libgit2-dev', 'reference': '0.25.1+really0.24.6-1+deb9u1'}
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
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libgit2-24 / libgit2-dev');
}
