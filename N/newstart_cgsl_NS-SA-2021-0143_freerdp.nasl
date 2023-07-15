#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0143. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154493);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/27");

  script_cve_id(
    "CVE-2020-11521",
    "CVE-2020-11523",
    "CVE-2020-11524",
    "CVE-2020-13398"
  );

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : freerdp Multiple Vulnerabilities (NS-SA-2021-0143)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has freerdp packages installed that are affected
by multiple vulnerabilities:

  - libfreerdp/codec/planar.c in FreeRDP version > 1.0 through 2.0.0-rc4 has an Out-of-bounds Write.
    (CVE-2020-11521)

  - libfreerdp/gdi/region.c in FreeRDP versions > 1.0 through 2.0.0-rc4 has an Integer Overflow.
    (CVE-2020-11523)

  - libfreerdp/codec/interleaved.c in FreeRDP versions > 1.0 through 2.0.0-rc4 has an Out-of-bounds Write.
    (CVE-2020-11524)

  - An issue was discovered in FreeRDP before 2.1.1. An out-of-bounds (OOB) write vulnerability has been
    detected in crypto_rsa_common in libfreerdp/crypto/crypto.c. (CVE-2020-13398)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0143");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-11521");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-11523");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-11524");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-13398");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL freerdp packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13398");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:freerdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:freerdp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:freerdp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:freerdp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libwinpr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libwinpr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:freerdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:freerdp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:freerdp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:freerdp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libwinpr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libwinpr-devel");
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
    'freerdp-2.0.0-4.rc4.el7_8.1',
    'freerdp-debuginfo-2.0.0-4.rc4.el7_8.1',
    'freerdp-devel-2.0.0-4.rc4.el7_8.1',
    'freerdp-libs-2.0.0-4.rc4.el7_8.1',
    'libwinpr-2.0.0-4.rc4.el7_8.1',
    'libwinpr-devel-2.0.0-4.rc4.el7_8.1'
  ],
  'CGSL MAIN 5.05': [
    'freerdp-2.0.0-4.rc4.el7_8.1',
    'freerdp-debuginfo-2.0.0-4.rc4.el7_8.1',
    'freerdp-devel-2.0.0-4.rc4.el7_8.1',
    'freerdp-libs-2.0.0-4.rc4.el7_8.1',
    'libwinpr-2.0.0-4.rc4.el7_8.1',
    'libwinpr-devel-2.0.0-4.rc4.el7_8.1'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'freerdp');
}
