#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0181. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154455);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/27");

  script_cve_id("CVE-2021-21261");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : flatpak Vulnerability (NS-SA-2021-0181)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has flatpak packages installed that are affected
by a vulnerability:

  - Flatpak is a system for building, distributing, and running sandboxed desktop applications on Linux. A bug
    was discovered in the `flatpak-portal` service that can allow sandboxed applications to execute arbitrary
    code on the host system (a sandbox escape). This sandbox-escape bug is present in versions from 0.11.4 and
    before fixed versions 1.8.5 and 1.10.0. The Flatpak portal D-Bus service (`flatpak-portal`, also known by
    its D-Bus service name `org.freedesktop.portal.Flatpak`) allows apps in a Flatpak sandbox to launch their
    own subprocesses in a new sandbox instance, either with the same security settings as the caller or with
    more restrictive security settings. For example, this is used in Flatpak-packaged web browsers such as
    Chromium to launch subprocesses that will process untrusted web content, and give those subprocesses a
    more restrictive sandbox than the browser itself. In vulnerable versions, the Flatpak portal service
    passes caller-specified environment variables to non-sandboxed processes on the host system, and in
    particular to the `flatpak run` command that is used to launch the new sandbox instance. A malicious or
    compromised Flatpak app could set environment variables that are trusted by the `flatpak run` command, and
    use them to execute arbitrary code that is not in a sandbox. As a workaround, this vulnerability can be
    mitigated by preventing the `flatpak-portal` service from starting, but that mitigation will prevent many
    Flatpak apps from working correctly. This is fixed in versions 1.8.5 and 1.10.0. (CVE-2021-21261)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0181");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-21261");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL flatpak packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21261");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:flatpak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:flatpak-builder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:flatpak-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:flatpak-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:flatpak-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:flatpak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:flatpak-builder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:flatpak-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:flatpak-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:flatpak-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.05': [
    'flatpak-1.0.9-10.el7_9',
    'flatpak-builder-1.0.0-10.el7_9',
    'flatpak-debuginfo-1.0.9-10.el7_9',
    'flatpak-devel-1.0.9-10.el7_9',
    'flatpak-libs-1.0.9-10.el7_9'
  ],
  'CGSL MAIN 5.05': [
    'flatpak-1.0.9-10.el7_9',
    'flatpak-builder-1.0.0-10.el7_9',
    'flatpak-debuginfo-1.0.9-10.el7_9',
    'flatpak-devel-1.0.9-10.el7_9',
    'flatpak-libs-1.0.9-10.el7_9'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'flatpak');
}
