#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2876. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156575);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/21");

  script_cve_id(
    "CVE-2017-17087",
    "CVE-2019-20807",
    "CVE-2021-3778",
    "CVE-2021-3796"
  );
  script_xref(name:"IAVB", value:"2020-B-0053-S");

  script_name(english:"Debian DLA-2876-1 : vim - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2876 advisory.

  - fileio.c in Vim prior to 8.0.1263 sets the group ownership of a .swp file to the editor's primary group
    (which may be different from the group ownership of the original file), which allows local users to obtain
    sensitive information by leveraging an applicable group membership, as demonstrated by /etc/shadow owned
    by root:shadow mode 0640, but /etc/.shadow.swp owned by root:users mode 0640, a different vulnerability
    than CVE-2017-1000382. (CVE-2017-17087)

  - In Vim before 8.1.0881, users can circumvent the rvim restricted mode and execute arbitrary OS commands
    via scripting interfaces (e.g., Python, Ruby, or Lua). (CVE-2019-20807)

  - vim is vulnerable to Heap-based Buffer Overflow (CVE-2021-3778)

  - vim is vulnerable to Use After Free (CVE-2021-3796)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/vim");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2876");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-17087");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-20807");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3778");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3796");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/vim");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vim packages.

For Debian 9 stretch, these problems have been fixed in version 2");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3796");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3778");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-athena");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-gui-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-tiny");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xxd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
    {'release': '9.0', 'prefix': 'vim', 'reference': '2:8.0.0197-4+deb9u4'},
    {'release': '9.0', 'prefix': 'vim-athena', 'reference': '2:8.0.0197-4+deb9u4'},
    {'release': '9.0', 'prefix': 'vim-common', 'reference': '2:8.0.0197-4+deb9u4'},
    {'release': '9.0', 'prefix': 'vim-doc', 'reference': '2:8.0.0197-4+deb9u4'},
    {'release': '9.0', 'prefix': 'vim-gnome', 'reference': '2:8.0.0197-4+deb9u4'},
    {'release': '9.0', 'prefix': 'vim-gtk', 'reference': '2:8.0.0197-4+deb9u4'},
    {'release': '9.0', 'prefix': 'vim-gtk3', 'reference': '2:8.0.0197-4+deb9u4'},
    {'release': '9.0', 'prefix': 'vim-gui-common', 'reference': '2:8.0.0197-4+deb9u4'},
    {'release': '9.0', 'prefix': 'vim-nox', 'reference': '2:8.0.0197-4+deb9u4'},
    {'release': '9.0', 'prefix': 'vim-runtime', 'reference': '2:8.0.0197-4+deb9u4'},
    {'release': '9.0', 'prefix': 'vim-tiny', 'reference': '2:8.0.0197-4+deb9u4'},
    {'release': '9.0', 'prefix': 'xxd', 'reference': '2:8.0.0197-4+deb9u4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'vim / vim-athena / vim-common / vim-doc / vim-gnome / vim-gtk / etc');
}
