#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2705. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151480);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/08");

  script_cve_id(
    "CVE-2021-30485",
    "CVE-2021-31229",
    "CVE-2021-31347",
    "CVE-2021-31348",
    "CVE-2021-31598"
  );

  script_name(english:"Debian DLA-2705-1 : scilab - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2705 advisory.

  - An issue was discovered in libezxml.a in ezXML 0.8.6. The function ezxml_internal_dtd(), while parsing a
    crafted XML file, performs incorrect memory handling, leading to a NULL pointer dereference while running
    strcmp() on a NULL pointer. (CVE-2021-30485)

  - An issue was discovered in libezxml.a in ezXML 0.8.6. The function ezxml_internal_dtd() performs incorrect
    memory handling while parsing crafted XML files, which leads to an out-of-bounds write of a one byte
    constant. (CVE-2021-31229)

  - An issue was discovered in libezxml.a in ezXML 0.8.6. The function ezxml_parse_str() performs incorrect
    memory handling while parsing crafted XML files (writing outside a memory region created by mmap).
    (CVE-2021-31347)

  - An issue was discovered in libezxml.a in ezXML 0.8.6. The function ezxml_parse_str() performs incorrect
    memory handling while parsing crafted XML files (out-of-bounds read after a certain strcspn failure).
    (CVE-2021-31348)

  - An issue was discovered in libezxml.a in ezXML 0.8.6. The function ezxml_decode() performs incorrect
    memory handling while parsing crafted XML files, leading to a heap-based buffer overflow. (CVE-2021-31598)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/scilab");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2705");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-30485");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-31229");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-31347");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-31348");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-31598");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/scilab");
  script_set_attribute(attribute:"solution", value:
"Upgrade the scilab packages.

For Debian 9 stretch, these problems have been fixed in version 5.5.2-4+deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31598");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scilab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scilab-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scilab-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scilab-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scilab-doc-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scilab-doc-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scilab-doc-pt-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scilab-full-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scilab-full-bin-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scilab-include");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scilab-minimal-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scilab-minimal-bin-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scilab-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '9.0', 'prefix': 'scilab', 'reference': '5.5.2-4+deb9u1'},
    {'release': '9.0', 'prefix': 'scilab-cli', 'reference': '5.5.2-4+deb9u1'},
    {'release': '9.0', 'prefix': 'scilab-data', 'reference': '5.5.2-4+deb9u1'},
    {'release': '9.0', 'prefix': 'scilab-doc', 'reference': '5.5.2-4+deb9u1'},
    {'release': '9.0', 'prefix': 'scilab-doc-fr', 'reference': '5.5.2-4+deb9u1'},
    {'release': '9.0', 'prefix': 'scilab-doc-ja', 'reference': '5.5.2-4+deb9u1'},
    {'release': '9.0', 'prefix': 'scilab-doc-pt-br', 'reference': '5.5.2-4+deb9u1'},
    {'release': '9.0', 'prefix': 'scilab-full-bin', 'reference': '5.5.2-4+deb9u1'},
    {'release': '9.0', 'prefix': 'scilab-full-bin-dbg', 'reference': '5.5.2-4+deb9u1'},
    {'release': '9.0', 'prefix': 'scilab-include', 'reference': '5.5.2-4+deb9u1'},
    {'release': '9.0', 'prefix': 'scilab-minimal-bin', 'reference': '5.5.2-4+deb9u1'},
    {'release': '9.0', 'prefix': 'scilab-minimal-bin-dbg', 'reference': '5.5.2-4+deb9u1'},
    {'release': '9.0', 'prefix': 'scilab-test', 'reference': '5.5.2-4+deb9u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'scilab / scilab-cli / scilab-data / scilab-doc / scilab-doc-fr / etc');
}
