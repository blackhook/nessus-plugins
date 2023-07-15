#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5059. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157259);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/16");

  script_cve_id("CVE-2021-4034");
  script_xref(name:"IAVA", value:"2022-A-0055");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/18");

  script_name(english:"Debian DSA-5059-1 : policykit-1 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 / 11 host has packages installed that are affected by a vulnerability as referenced in the dsa-5059
advisory.

  - A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is
    a setuid tool designed to allow unprivileged users to run commands as privileged users according
    predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly
    and ends trying to execute environment variables as commands. An attacker can leverage this by crafting
    environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully
    executed the attack can cause a local privilege escalation given unprivileged users administrative rights
    on the target machine. (CVE-2021-4034)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/policykit-1");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5059");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4034");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/policykit-1");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/policykit-1");
  script_set_attribute(attribute:"solution", value:
"Upgrade the policykit-1 packages.

For the stable distribution (bullseye), this problem has been fixed in version 0.105-31+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4034");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Local Privilege Escalation in polkits pkexec');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-polkit-1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpolkit-agent-1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpolkit-agent-1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpolkit-backend-1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpolkit-backend-1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpolkit-gobject-1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpolkit-gobject-1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:policykit-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:policykit-1-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(10)\.[0-9]+|^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0 / 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'gir1.2-polkit-1.0', 'reference': '0.105-25+deb10u1'},
    {'release': '10.0', 'prefix': 'libpolkit-agent-1-0', 'reference': '0.105-25+deb10u1'},
    {'release': '10.0', 'prefix': 'libpolkit-agent-1-dev', 'reference': '0.105-25+deb10u1'},
    {'release': '10.0', 'prefix': 'libpolkit-backend-1-0', 'reference': '0.105-25+deb10u1'},
    {'release': '10.0', 'prefix': 'libpolkit-backend-1-dev', 'reference': '0.105-25+deb10u1'},
    {'release': '10.0', 'prefix': 'libpolkit-gobject-1-0', 'reference': '0.105-25+deb10u1'},
    {'release': '10.0', 'prefix': 'libpolkit-gobject-1-dev', 'reference': '0.105-25+deb10u1'},
    {'release': '10.0', 'prefix': 'policykit-1', 'reference': '0.105-25+deb10u1'},
    {'release': '10.0', 'prefix': 'policykit-1-doc', 'reference': '0.105-25+deb10u1'},
    {'release': '11.0', 'prefix': 'gir1.2-polkit-1.0', 'reference': '0.105-31+deb11u1'},
    {'release': '11.0', 'prefix': 'libpolkit-agent-1-0', 'reference': '0.105-31+deb11u1'},
    {'release': '11.0', 'prefix': 'libpolkit-agent-1-dev', 'reference': '0.105-31+deb11u1'},
    {'release': '11.0', 'prefix': 'libpolkit-backend-1-0', 'reference': '0.105-31+deb11u1'},
    {'release': '11.0', 'prefix': 'libpolkit-backend-1-dev', 'reference': '0.105-31+deb11u1'},
    {'release': '11.0', 'prefix': 'libpolkit-gobject-1-0', 'reference': '0.105-31+deb11u1'},
    {'release': '11.0', 'prefix': 'libpolkit-gobject-1-dev', 'reference': '0.105-31+deb11u1'},
    {'release': '11.0', 'prefix': 'policykit-1', 'reference': '0.105-31+deb11u1'},
    {'release': '11.0', 'prefix': 'policykit-1-doc', 'reference': '0.105-31+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gir1.2-polkit-1.0 / libpolkit-agent-1-0 / libpolkit-agent-1-dev / etc');
}
