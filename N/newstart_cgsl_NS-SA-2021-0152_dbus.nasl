#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0152. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154467);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/27");

  script_cve_id("CVE-2019-12749");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : dbus Vulnerability (NS-SA-2021-0152)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has dbus packages installed that are affected by a
vulnerability:

  - dbus before 1.10.28, 1.12.x before 1.12.16, and 1.13.x before 1.13.12, as used in DBusServer in Canonical
    Upstart in Ubuntu 14.04 (and in some, less common, uses of dbus-daemon), allows cookie spoofing because of
    symlink mishandling in the reference implementation of DBUS_COOKIE_SHA1 in the libdbus library. (This only
    affects the DBUS_COOKIE_SHA1 authentication mechanism.) A malicious client with write access to its own
    home directory could manipulate a ~/.dbus-keyrings symlink to cause a DBusServer with a different uid to
    read and write in unintended locations. In the worst case, this could result in the DBusServer reusing a
    cookie that is known to the malicious client, and treating that cookie as evidence that a subsequent
    client connection came from an attacker-chosen uid, allowing authentication bypass. (CVE-2019-12749)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0152");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-12749");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL dbus packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12749");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:dbus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:dbus-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:dbus-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:dbus-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:dbus-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:dbus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:dbus-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:dbus-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:dbus-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:dbus-x11");
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
    'dbus-1.10.24-15.el7.cgslv5_5.0.2.g0c4cd58',
    'dbus-devel-1.10.24-15.el7.cgslv5_5.0.2.g0c4cd58',
    'dbus-doc-1.10.24-15.el7.cgslv5_5.0.2.g0c4cd58',
    'dbus-libs-1.10.24-15.el7.cgslv5_5.0.2.g0c4cd58',
    'dbus-tests-1.10.24-15.el7.cgslv5_5.0.2.g0c4cd58',
    'dbus-x11-1.10.24-15.el7.cgslv5_5.0.2.g0c4cd58'
  ],
  'CGSL MAIN 5.05': [
    'dbus-1.10.24-15.el7.cgslv5_5.0.2.g0c4cd58',
    'dbus-devel-1.10.24-15.el7.cgslv5_5.0.2.g0c4cd58',
    'dbus-doc-1.10.24-15.el7.cgslv5_5.0.2.g0c4cd58',
    'dbus-libs-1.10.24-15.el7.cgslv5_5.0.2.g0c4cd58',
    'dbus-tests-1.10.24-15.el7.cgslv5_5.0.2.g0c4cd58',
    'dbus-x11-1.10.24-15.el7.cgslv5_5.0.2.g0c4cd58'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dbus');
}
