##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0066. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160793);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id("CVE-2020-29361", "CVE-2020-29362", "CVE-2020-29363");

  script_name(english:"NewStart CGSL MAIN 6.02 : p11-kit Multiple Vulnerabilities (NS-SA-2022-0066)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has p11-kit packages installed that are affected by multiple
vulnerabilities:

  - An issue was discovered in p11-kit 0.21.1 through 0.23.21. Multiple integer overflows have been discovered
    in the array allocations in the p11-kit library and the p11-kit list command, where overflow checks are
    missing before calling realloc or calloc. (CVE-2020-29361)

  - An issue was discovered in p11-kit 0.21.1 through 0.23.21. A heap-based buffer over-read has been
    discovered in the RPC protocol used by thep11-kit server/remote commands and the client library. When the
    remote entity supplies a byte array through a serialized PKCS#11 function call, the receiving entity may
    allow the reading of up to 4 bytes of memory past the heap allocation. (CVE-2020-29362)

  - An issue was discovered in p11-kit 0.23.6 through 0.23.21. A heap-based buffer overflow has been
    discovered in the RPC protocol used by p11-kit server/remote commands and the client library. When the
    remote entity supplies a serialized byte array in a CK_ATTRIBUTE, the receiving entity may not allocate
    sufficient length for the buffer to store the deserialized value. (CVE-2020-29363)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0066");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-29361");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-29362");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-29363");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL p11-kit packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-29362");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:p11-kit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:p11-kit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:p11-kit-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:p11-kit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:p11-kit-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:p11-kit-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:p11-kit-trust");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:p11-kit-trust-debuginfo");
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
    'p11-kit-0.23.22-1.el8',
    'p11-kit-debuginfo-0.23.22-1.el8',
    'p11-kit-debugsource-0.23.22-1.el8',
    'p11-kit-devel-0.23.22-1.el8',
    'p11-kit-server-0.23.22-1.el8',
    'p11-kit-server-debuginfo-0.23.22-1.el8',
    'p11-kit-trust-0.23.22-1.el8',
    'p11-kit-trust-debuginfo-0.23.22-1.el8'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'p11-kit');
}
