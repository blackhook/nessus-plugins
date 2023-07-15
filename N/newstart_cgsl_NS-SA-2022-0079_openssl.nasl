#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0079. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167282);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/14");

  script_cve_id("CVE-2022-1292");
  script_xref(name:"IAVA", value:"2022-A-0186-S");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : openssl Vulnerability (NS-SA-2022-0079)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has openssl packages installed that are affected
by a vulnerability:

  - The c_rehash script does not properly sanitise shell metacharacters to prevent command injection. This
    script is distributed by some operating systems in a manner where it is automatically executed. On such
    operating systems, an attacker could execute arbitrary commands with the privileges of the script. Use of
    the c_rehash script is considered obsolete and should be replaced by the OpenSSL rehash command line tool.
    Fixed in OpenSSL 3.0.3 (Affected 3.0.0,3.0.1,3.0.2). Fixed in OpenSSL 1.1.1o (Affected 1.1.1-1.1.1n).
    Fixed in OpenSSL 1.0.2ze (Affected 1.0.2-1.0.2zd). (CVE-2022-1292)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0079");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-1292");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL openssl packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1292");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:openssl-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:openssl-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL CORE 5.04" &&
    os_release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.04': [
    'openssl-1.0.2k-25.el7_9.cgslv5.0.3.g9f3ad29.lite',
    'openssl-crypto-1.0.2k-25.el7_9.cgslv5.0.3.g9f3ad29.lite',
    'openssl-debuginfo-1.0.2k-25.el7_9.cgslv5.0.3.g9f3ad29.lite',
    'openssl-devel-1.0.2k-25.el7_9.cgslv5.0.3.g9f3ad29.lite',
    'openssl-libs-1.0.2k-25.el7_9.cgslv5.0.3.g9f3ad29.lite',
    'openssl-perl-1.0.2k-25.el7_9.cgslv5.0.3.g9f3ad29.lite',
    'openssl-static-1.0.2k-25.el7_9.cgslv5.0.3.g9f3ad29.lite'
  ],
  'CGSL MAIN 5.04': [
    'openssl-1.0.2k-25.el7_9.cgslv5.0.2.gc80e85d',
    'openssl-debuginfo-1.0.2k-25.el7_9.cgslv5.0.2.gc80e85d',
    'openssl-devel-1.0.2k-25.el7_9.cgslv5.0.2.gc80e85d',
    'openssl-libs-1.0.2k-25.el7_9.cgslv5.0.2.gc80e85d',
    'openssl-perl-1.0.2k-25.el7_9.cgslv5.0.2.gc80e85d',
    'openssl-static-1.0.2k-25.el7_9.cgslv5.0.2.gc80e85d'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openssl');
}
