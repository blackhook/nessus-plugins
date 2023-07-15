#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2023-0012. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174082);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/11");

  script_cve_id("CVE-2021-41133");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : flatpak Vulnerability (NS-SA-2023-0012)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has flatpak packages installed that are affected
by a vulnerability:

  - Flatpak is a system for building, distributing, and running sandboxed desktop applications on Linux. In
    versions prior to 1.10.4 and 1.12.0, Flatpak apps with direct access to AF_UNIX sockets such as those used
    by Wayland, Pipewire or pipewire-pulse can trick portals and other host-OS services into treating the
    Flatpak app as though it was an ordinary, non-sandboxed host-OS process. They can do this by manipulating
    the VFS using recent mount-related syscalls that are not blocked by Flatpak's denylist seccomp filter, in
    order to substitute a crafted `/.flatpak-info` or make that file disappear entirely. Flatpak apps that act
    as clients for AF_UNIX sockets such as those used by Wayland, Pipewire or pipewire-pulse can escalate the
    privileges that the corresponding services will believe the Flatpak app has. Note that protocols that
    operate entirely over the D-Bus session bus (user bus), system bus or accessibility bus are not affected
    by this. This is due to the use of a proxy process `xdg-dbus-proxy`, whose VFS cannot be manipulated by
    the Flatpak app, when interacting with these buses. Patches exist for versions 1.10.4 and 1.12.0, and as
    of time of publication, a patch for version 1.8.2 is being planned. There are no workarounds aside from
    upgrading to a patched version. (CVE-2021-41133)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2023-0012");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-41133");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL flatpak packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41133");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/11");

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
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL CORE 5.05" &&
    os_release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.05': [
    'flatpak-1.0.9-12.el7_9',
    'flatpak-builder-1.0.0-12.el7_9',
    'flatpak-debuginfo-1.0.9-12.el7_9',
    'flatpak-devel-1.0.9-12.el7_9',
    'flatpak-libs-1.0.9-12.el7_9'
  ],
  'CGSL MAIN 5.05': [
    'flatpak-1.0.9-12.el7_9',
    'flatpak-builder-1.0.0-12.el7_9',
    'flatpak-debuginfo-1.0.9-12.el7_9',
    'flatpak-devel-1.0.9-12.el7_9',
    'flatpak-libs-1.0.9-12.el7_9'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
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
