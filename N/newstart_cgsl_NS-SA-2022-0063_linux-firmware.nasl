##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0063. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160744);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id("CVE-2020-12362", "CVE-2020-12363", "CVE-2020-12364");

  script_name(english:"NewStart CGSL MAIN 6.02 : linux-firmware Multiple Vulnerabilities (NS-SA-2022-0063)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has linux-firmware packages installed that are affected by
multiple vulnerabilities:

  - Integer overflow in the firmware for some Intel(R) Graphics Drivers for Windows * before version
    26.20.100.7212 and before Linux kernel version 5.5 may allow a privileged user to potentially enable an
    escalation of privilege via local access. (CVE-2020-12362)

  - Improper input validation in some Intel(R) Graphics Drivers for Windows* before version 26.20.100.7212 and
    before Linux kernel version 5.5 may allow a privileged user to potentially enable a denial of service via
    local access. (CVE-2020-12363)

  - Null pointer reference in some Intel(R) Graphics Drivers for Windows* before version 26.20.100.7212 and
    before version Linux kernel version 5.5 may allow a privileged user to potentially enable a denial of
    service via local access. (CVE-2020-12364)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0063");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-12362");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-12363");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-12364");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL linux-firmware packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12362");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libertas-sd8686-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libertas-sd8787-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libertas-usb8388-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libertas-usb8388-olpc-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:linux-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'iwl100-firmware-39.31.5.1-102.el8.1',
    'iwl1000-firmware-39.31.5.1-102.el8.1',
    'iwl105-firmware-18.168.6.1-102.el8.1',
    'iwl135-firmware-18.168.6.1-102.el8.1',
    'iwl2000-firmware-18.168.6.1-102.el8.1',
    'iwl2030-firmware-18.168.6.1-102.el8.1',
    'iwl3160-firmware-25.30.13.0-102.el8.1',
    'iwl3945-firmware-15.32.2.9-102.el8.1',
    'iwl4965-firmware-228.61.2.24-102.el8.1',
    'iwl5000-firmware-8.83.5.1_1-102.el8.1',
    'iwl5150-firmware-8.24.2.2-102.el8.1',
    'iwl6000-firmware-9.221.4.1-102.el8.1',
    'iwl6000g2a-firmware-18.168.6.1-102.el8.1',
    'iwl6000g2b-firmware-18.168.6.1-102.el8.1',
    'iwl6050-firmware-41.28.5.1-102.el8.1',
    'iwl7260-firmware-25.30.13.0-102.el8.1',
    'libertas-sd8686-firmware-20201218-102.git05789708.el8',
    'libertas-sd8787-firmware-20201218-102.git05789708.el8',
    'libertas-usb8388-firmware-20201218-102.git05789708.el8',
    'libertas-usb8388-olpc-firmware-20201218-102.git05789708.el8',
    'linux-firmware-20201218-102.git05789708.el8'
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
