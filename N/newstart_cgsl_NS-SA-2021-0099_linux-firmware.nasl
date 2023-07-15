#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0099. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154536);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/27");

  script_cve_id("CVE-2020-12321");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : linux-firmware Vulnerability (NS-SA-2021-0099)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has linux-firmware packages installed that are
affected by a vulnerability:

  - Improper buffer restriction in some Intel(R) Wireless Bluetooth(R) products before version 21.110 may
    allow an unauthenticated user to potentially enable escalation of privilege via adjacent access.
    (CVE-2020-12321)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0099");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-12321");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL linux-firmware packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12321");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:iwl100-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:iwl1000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:iwl105-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:iwl135-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:iwl2000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:iwl2030-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:iwl3160-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:iwl3945-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:iwl4965-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:iwl5000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:iwl5150-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:iwl6000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:iwl6000g2a-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:iwl6000g2b-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:iwl6050-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:iwl7260-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:linux-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:linux-firmware-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:linux-firmware-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:iwl100-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:iwl1000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:iwl105-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:iwl135-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:iwl2000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:iwl2030-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:iwl3160-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:iwl3945-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:iwl4965-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:iwl5000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:iwl5150-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:iwl6000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:iwl6000g2a-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:iwl6000g2b-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:iwl6050-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:iwl7260-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:linux-firmware");
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

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.04': [
    'iwl100-firmware-39.31.5.1-80.el7_9.cgslv5.0.4.g9da9570.lite',
    'iwl1000-firmware-39.31.5.1-80.el7_9.cgslv5.0.4.g9da9570.lite',
    'iwl105-firmware-18.168.6.1-80.el7_9.cgslv5.0.4.g9da9570.lite',
    'iwl135-firmware-18.168.6.1-80.el7_9.cgslv5.0.4.g9da9570.lite',
    'iwl2000-firmware-18.168.6.1-80.el7_9.cgslv5.0.4.g9da9570.lite',
    'iwl2030-firmware-18.168.6.1-80.el7_9.cgslv5.0.4.g9da9570.lite',
    'iwl3160-firmware-25.30.13.0-80.el7_9.cgslv5.0.4.g9da9570.lite',
    'iwl3945-firmware-15.32.2.9-80.el7_9.cgslv5.0.4.g9da9570.lite',
    'iwl4965-firmware-228.61.2.24-80.el7_9.cgslv5.0.4.g9da9570.lite',
    'iwl5000-firmware-8.83.5.1_1-80.el7_9.cgslv5.0.4.g9da9570.lite',
    'iwl5150-firmware-8.24.2.2-80.el7_9.cgslv5.0.4.g9da9570.lite',
    'iwl6000-firmware-9.221.4.1-80.el7_9.cgslv5.0.4.g9da9570.lite',
    'iwl6000g2a-firmware-18.168.6.1-80.el7_9.cgslv5.0.4.g9da9570.lite',
    'iwl6000g2b-firmware-18.168.6.1-80.el7_9.cgslv5.0.4.g9da9570.lite',
    'iwl6050-firmware-41.28.5.1-80.el7_9.cgslv5.0.4.g9da9570.lite',
    'iwl7260-firmware-25.30.13.0-80.el7_9.cgslv5.0.4.g9da9570.lite',
    'linux-firmware-20200421-80.git78c0348.el7_9.cgslv5.0.4.g9da9570.lite',
    'linux-firmware-core-20200421-80.git78c0348.el7_9.cgslv5.0.4.g9da9570.lite',
    'linux-firmware-other-20200421-80.git78c0348.el7_9.cgslv5.0.4.g9da9570.lite'
  ],
  'CGSL MAIN 5.04': [
    'iwl100-firmware-39.31.5.1-80.el7_9.cgslv5',
    'iwl1000-firmware-39.31.5.1-80.el7_9.cgslv5',
    'iwl105-firmware-18.168.6.1-80.el7_9.cgslv5',
    'iwl135-firmware-18.168.6.1-80.el7_9.cgslv5',
    'iwl2000-firmware-18.168.6.1-80.el7_9.cgslv5',
    'iwl2030-firmware-18.168.6.1-80.el7_9.cgslv5',
    'iwl3160-firmware-25.30.13.0-80.el7_9.cgslv5',
    'iwl3945-firmware-15.32.2.9-80.el7_9.cgslv5',
    'iwl4965-firmware-228.61.2.24-80.el7_9.cgslv5',
    'iwl5000-firmware-8.83.5.1_1-80.el7_9.cgslv5',
    'iwl5150-firmware-8.24.2.2-80.el7_9.cgslv5',
    'iwl6000-firmware-9.221.4.1-80.el7_9.cgslv5',
    'iwl6000g2a-firmware-18.168.6.1-80.el7_9.cgslv5',
    'iwl6000g2b-firmware-18.168.6.1-80.el7_9.cgslv5',
    'iwl6050-firmware-41.28.5.1-80.el7_9.cgslv5',
    'iwl7260-firmware-25.30.13.0-80.el7_9.cgslv5',
    'linux-firmware-20200421-80.git78c0348.el7_9.cgslv5'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-firmware');
}
