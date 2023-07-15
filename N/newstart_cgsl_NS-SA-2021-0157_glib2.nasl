#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0157. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154598);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/28");

  script_cve_id("CVE-2019-12450");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : glib2 Vulnerability (NS-SA-2021-0157)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has glib2 packages installed that are affected by
a vulnerability:

  - file_copy_fallback in gio/gfile.c in GNOME GLib 2.15.0 through 2.61.1 does not properly restrict file
    permissions while a copy operation is in progress. Instead, default permissions are used. (CVE-2019-12450)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0157");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-12450");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL glib2 packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12450");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:glib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:glib2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:glib2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:glib2-fam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:glib2-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:glib2-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:glib2-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glib2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glib2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glib2-fam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glib2-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glib2-tests");
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
    'glib2-2.56.1-8.el7.cgslv5_5.0.1.g8273ee0.lite',
    'glib2-devel-2.56.1-8.el7.cgslv5_5.0.1.g8273ee0.lite',
    'glib2-doc-2.56.1-8.el7.cgslv5_5.0.1.g8273ee0.lite',
    'glib2-fam-2.56.1-8.el7.cgslv5_5.0.1.g8273ee0.lite',
    'glib2-libs-2.56.1-8.el7.cgslv5_5.0.1.g8273ee0.lite',
    'glib2-static-2.56.1-8.el7.cgslv5_5.0.1.g8273ee0.lite',
    'glib2-tests-2.56.1-8.el7.cgslv5_5.0.1.g8273ee0.lite'
  ],
  'CGSL MAIN 5.05': [
    'glib2-2.56.1-8.el7.cgslv5_5',
    'glib2-devel-2.56.1-8.el7.cgslv5_5',
    'glib2-doc-2.56.1-8.el7.cgslv5_5',
    'glib2-fam-2.56.1-8.el7.cgslv5_5',
    'glib2-static-2.56.1-8.el7.cgslv5_5',
    'glib2-tests-2.56.1-8.el7.cgslv5_5'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'glib2');
}
