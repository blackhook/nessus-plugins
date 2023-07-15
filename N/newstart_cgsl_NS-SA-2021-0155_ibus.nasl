#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0155. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154578);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/27");

  script_cve_id("CVE-2019-14822");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : ibus Vulnerability (NS-SA-2021-0155)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has ibus packages installed that are affected by a
vulnerability:

  - A flaw was discovered in ibus in versions before 1.5.22 that allows any unprivileged user to monitor and
    send method calls to the ibus bus of another user due to a misconfiguration in the DBus server setup. A
    local attacker may use this flaw to intercept all keystrokes of a victim user who is using the graphical
    interface, change the input method engine, or modify other input related configurations of the victim
    user. (CVE-2019-14822)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0155");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-14822");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL ibus packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14822");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:ibus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:ibus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:ibus-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:ibus-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:ibus-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:ibus-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:ibus-pygtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:ibus-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:ibus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:ibus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:ibus-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:ibus-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:ibus-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:ibus-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:ibus-pygtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:ibus-setup");
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
    'ibus-1.5.17-12.el7_9',
    'ibus-devel-1.5.17-12.el7_9',
    'ibus-devel-docs-1.5.17-12.el7_9',
    'ibus-gtk2-1.5.17-12.el7_9',
    'ibus-gtk3-1.5.17-12.el7_9',
    'ibus-libs-1.5.17-12.el7_9',
    'ibus-pygtk2-1.5.17-12.el7_9',
    'ibus-setup-1.5.17-12.el7_9'
  ],
  'CGSL MAIN 5.05': [
    'ibus-1.5.17-12.el7_9',
    'ibus-devel-1.5.17-12.el7_9',
    'ibus-devel-docs-1.5.17-12.el7_9',
    'ibus-gtk2-1.5.17-12.el7_9',
    'ibus-gtk3-1.5.17-12.el7_9',
    'ibus-libs-1.5.17-12.el7_9',
    'ibus-pygtk2-1.5.17-12.el7_9',
    'ibus-setup-1.5.17-12.el7_9'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ibus');
}
