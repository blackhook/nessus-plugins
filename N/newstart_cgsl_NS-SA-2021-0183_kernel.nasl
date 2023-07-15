#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0183. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154444);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/27");

  script_cve_id("CVE-2020-10769", "CVE-2020-14314");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : kernel Multiple Vulnerabilities (NS-SA-2021-0183)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has kernel packages installed that are affected by
multiple vulnerabilities:

  - A buffer over-read flaw was found in RH kernel versions before 5.0 in crypto_authenc_extractkeys in
    crypto/authenc.c in the IPsec Cryptographic algorithm's module, authenc. When a payload longer than 4
    bytes, and is not following 4-byte alignment boundary guidelines, it causes a buffer over-read threat,
    leading to a system crash. This flaw allows a local attacker with user privileges to cause a denial of
    service. (CVE-2020-10769)

  - A memory out-of-bounds read flaw was found in the Linux kernel before 5.9-rc2 with the ext3/ext4 file
    system, in the way it accesses a directory with broken indexing. This flaw allows a local user to crash
    the system if the directory exists. The highest threat from this vulnerability is to system availability.
    (CVE-2020-14314)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0183");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-10769");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-14314");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14314");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python-perf-debuginfo");
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
    'bpftool-3.10.0-957.27.2.el7.cgslv5_5.19.276.g1c1331f.lite',
    'kernel-3.10.0-957.27.2.el7.cgslv5_5.19.276.g1c1331f.lite',
    'kernel-core-3.10.0-957.27.2.el7.cgslv5_5.19.276.g1c1331f.lite',
    'kernel-debug-core-3.10.0-957.27.2.el7.cgslv5_5.19.276.g1c1331f.lite',
    'kernel-debug-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.19.276.g1c1331f.lite',
    'kernel-debug-devel-3.10.0-957.27.2.el7.cgslv5_5.19.276.g1c1331f.lite',
    'kernel-debug-modules-3.10.0-957.27.2.el7.cgslv5_5.19.276.g1c1331f.lite',
    'kernel-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.19.276.g1c1331f.lite',
    'kernel-debuginfo-common-x86_64-3.10.0-957.27.2.el7.cgslv5_5.19.276.g1c1331f.lite',
    'kernel-devel-3.10.0-957.27.2.el7.cgslv5_5.19.276.g1c1331f.lite',
    'kernel-headers-3.10.0-957.27.2.el7.cgslv5_5.19.276.g1c1331f.lite',
    'kernel-modules-3.10.0-957.27.2.el7.cgslv5_5.19.276.g1c1331f.lite',
    'kernel-tools-3.10.0-957.27.2.el7.cgslv5_5.19.276.g1c1331f.lite',
    'kernel-tools-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.19.276.g1c1331f.lite',
    'kernel-tools-libs-3.10.0-957.27.2.el7.cgslv5_5.19.276.g1c1331f.lite',
    'kernel-tools-libs-devel-3.10.0-957.27.2.el7.cgslv5_5.19.276.g1c1331f.lite',
    'perf-3.10.0-957.27.2.el7.cgslv5_5.19.276.g1c1331f.lite',
    'perf-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.19.276.g1c1331f.lite',
    'python-perf-3.10.0-957.27.2.el7.cgslv5_5.19.276.g1c1331f.lite',
    'python-perf-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.19.276.g1c1331f.lite'
  ],
  'CGSL MAIN 5.05': [
    'bpftool-3.10.0-957.27.2.el7.cgslv5_5.20.327.g124bbcc',
    'kernel-3.10.0-957.27.2.el7.cgslv5_5.20.327.g124bbcc',
    'kernel-abi-whitelists-3.10.0-957.27.2.el7.cgslv5_5.20.327.g124bbcc',
    'kernel-debug-3.10.0-957.27.2.el7.cgslv5_5.20.327.g124bbcc',
    'kernel-debug-devel-3.10.0-957.27.2.el7.cgslv5_5.20.327.g124bbcc',
    'kernel-debuginfo-common-x86_64-3.10.0-957.27.2.el7.cgslv5_5.20.327.g124bbcc',
    'kernel-devel-3.10.0-957.27.2.el7.cgslv5_5.20.327.g124bbcc',
    'kernel-headers-3.10.0-957.27.2.el7.cgslv5_5.20.327.g124bbcc',
    'kernel-tools-3.10.0-957.27.2.el7.cgslv5_5.20.327.g124bbcc',
    'kernel-tools-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.20.327.g124bbcc',
    'kernel-tools-libs-3.10.0-957.27.2.el7.cgslv5_5.20.327.g124bbcc',
    'kernel-tools-libs-devel-3.10.0-957.27.2.el7.cgslv5_5.20.327.g124bbcc',
    'perf-3.10.0-957.27.2.el7.cgslv5_5.20.327.g124bbcc',
    'perf-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.20.327.g124bbcc',
    'python-perf-3.10.0-957.27.2.el7.cgslv5_5.20.327.g124bbcc',
    'python-perf-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.20.327.g124bbcc'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel');
}
