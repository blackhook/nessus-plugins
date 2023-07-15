#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3416. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(175551);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/13");

  script_cve_id("CVE-2022-48337", "CVE-2022-48339", "CVE-2023-28617");

  script_name(english:"Debian DLA-3416-1 : emacs - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3416 advisory.

  - GNU Emacs through 28.2 allows attackers to execute commands via shell metacharacters in the name of a
    source-code file, because lib-src/etags.c uses the system C library function in its implementation of the
    etags program. For example, a victim may use the etags -u * command (suggested in the etags
    documentation) in a situation where the current working directory has contents that depend on untrusted
    input. (CVE-2022-48337)

  - An issue was discovered in GNU Emacs through 28.2. htmlfontify.el has a command injection vulnerability.
    In the hfy-istext-command function, the parameter file and parameter srcdir come from external input, and
    parameters are not escaped. If a file name or directory name contains shell metacharacters, code may be
    executed. (CVE-2022-48339)

  - org-babel-execute:latex in ob-latex.el in Org Mode through 9.6.1 for GNU Emacs allows attackers to execute
    arbitrary commands via a file name or directory name that contains shell metacharacters. (CVE-2023-28617)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1031730");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/emacs");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3416");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-48337");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-48339");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-28617");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/emacs");
  script_set_attribute(attribute:"solution", value:
"Upgrade the emacs packages.

For Debian 10 buster, these problems have been fixed in version 1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48337");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs-bin-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs-lucid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs21-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs22-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs22-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs23-lucid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs23-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs24-lucid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs24-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs25");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs25-lucid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs25-nox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'emacs', 'reference': '1:26.1+1-3.2+deb10u4'},
    {'release': '10.0', 'prefix': 'emacs-bin-common', 'reference': '1:26.1+1-3.2+deb10u4'},
    {'release': '10.0', 'prefix': 'emacs-common', 'reference': '1:26.1+1-3.2+deb10u4'},
    {'release': '10.0', 'prefix': 'emacs-el', 'reference': '1:26.1+1-3.2+deb10u4'},
    {'release': '10.0', 'prefix': 'emacs-gtk', 'reference': '1:26.1+1-3.2+deb10u4'},
    {'release': '10.0', 'prefix': 'emacs-lucid', 'reference': '1:26.1+1-3.2+deb10u4'},
    {'release': '10.0', 'prefix': 'emacs-nox', 'reference': '1:26.1+1-3.2+deb10u4'},
    {'release': '10.0', 'prefix': 'emacs21', 'reference': '1:26.1+1-3.2+deb10u4'},
    {'release': '10.0', 'prefix': 'emacs21-nox', 'reference': '1:26.1+1-3.2+deb10u4'},
    {'release': '10.0', 'prefix': 'emacs22', 'reference': '1:26.1+1-3.2+deb10u4'},
    {'release': '10.0', 'prefix': 'emacs22-gtk', 'reference': '1:26.1+1-3.2+deb10u4'},
    {'release': '10.0', 'prefix': 'emacs22-nox', 'reference': '1:26.1+1-3.2+deb10u4'},
    {'release': '10.0', 'prefix': 'emacs23', 'reference': '1:26.1+1-3.2+deb10u4'},
    {'release': '10.0', 'prefix': 'emacs23-lucid', 'reference': '1:26.1+1-3.2+deb10u4'},
    {'release': '10.0', 'prefix': 'emacs23-nox', 'reference': '1:26.1+1-3.2+deb10u4'},
    {'release': '10.0', 'prefix': 'emacs24', 'reference': '1:26.1+1-3.2+deb10u4'},
    {'release': '10.0', 'prefix': 'emacs24-lucid', 'reference': '1:26.1+1-3.2+deb10u4'},
    {'release': '10.0', 'prefix': 'emacs24-nox', 'reference': '1:26.1+1-3.2+deb10u4'},
    {'release': '10.0', 'prefix': 'emacs25', 'reference': '1:26.1+1-3.2+deb10u4'},
    {'release': '10.0', 'prefix': 'emacs25-lucid', 'reference': '1:26.1+1-3.2+deb10u4'},
    {'release': '10.0', 'prefix': 'emacs25-nox', 'reference': '1:26.1+1-3.2+deb10u4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'emacs / emacs-bin-common / emacs-common / emacs-el / emacs-gtk / etc');
}
