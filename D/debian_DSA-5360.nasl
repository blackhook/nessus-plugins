#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5360. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(171900);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/03");

  script_cve_id("CVE-2022-48337", "CVE-2022-48338", "CVE-2022-48339");

  script_name(english:"Debian DSA-5360-1 : emacs - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5360 advisory.

  - GNU Emacs through 28.2 allows attackers to execute commands via shell metacharacters in the name of a
    source-code file, because lib-src/etags.c uses the system C library function in its implementation of the
    etags program. For example, a victim may use the etags -u * command (suggested in the etags
    documentation) in a situation where the current working directory has contents that depend on untrusted
    input. (CVE-2022-48337)

  - An issue was discovered in GNU Emacs through 28.2. In ruby-mode.el, the ruby-find-library-file function
    has a local command injection vulnerability. The ruby-find-library-file function is an interactive
    function, and bound to C-c C-f. Inside the function, the external command gem is called through shell-
    command-to-string, but the feature-name parameters are not escaped. Thus, malicious Ruby source files may
    cause commands to be executed. (CVE-2022-48338)

  - An issue was discovered in GNU Emacs through 28.2. htmlfontify.el has a command injection vulnerability.
    In the hfy-istext-command function, the parameter file and parameter srcdir come from external input, and
    parameters are not escaped. If a file name or directory name contains shell metacharacters, code may be
    executed. (CVE-2022-48339)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/emacs");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5360");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-48337");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-48338");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-48339");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/emacs");
  script_set_attribute(attribute:"solution", value:
"Upgrade the emacs packages.

For the stable distribution (bullseye), these problems have been fixed in version 1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48339");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs-bin-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs-lucid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs-nox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'emacs', 'reference': '1:27.1+1-3.1+deb11u2'},
    {'release': '11.0', 'prefix': 'emacs-bin-common', 'reference': '1:27.1+1-3.1+deb11u2'},
    {'release': '11.0', 'prefix': 'emacs-common', 'reference': '1:27.1+1-3.1+deb11u2'},
    {'release': '11.0', 'prefix': 'emacs-el', 'reference': '1:27.1+1-3.1+deb11u2'},
    {'release': '11.0', 'prefix': 'emacs-gtk', 'reference': '1:27.1+1-3.1+deb11u2'},
    {'release': '11.0', 'prefix': 'emacs-lucid', 'reference': '1:27.1+1-3.1+deb11u2'},
    {'release': '11.0', 'prefix': 'emacs-nox', 'reference': '1:27.1+1-3.1+deb11u2'}
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
