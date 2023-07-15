#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0098. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154531);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/27");

  script_cve_id(
    "CVE-2018-19824",
    "CVE-2019-5108",
    "CVE-2019-15214",
    "CVE-2019-15927"
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : kernel Multiple Vulnerabilities (NS-SA-2021-0098)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has kernel packages installed that are affected by
multiple vulnerabilities:

  - In the Linux kernel through 4.19.6, a local user could exploit a use-after-free in the ALSA driver by
    supplying a malicious USB Sound device (with zero interfaces) that is mishandled in usb_audio_probe in
    sound/usb/card.c. (CVE-2018-19824)

  - An issue was discovered in the Linux kernel before 5.0.10. There is a use-after-free in the sound
    subsystem because card disconnection causes certain data structures to be deleted too early. This is
    related to sound/core/init.c and sound/core/info.c. (CVE-2019-15214)

  - An issue was discovered in the Linux kernel before 4.20.2. An out-of-bounds access exists in the function
    build_audio_procunit in the file sound/usb/mixer.c. (CVE-2019-15927)

  - An exploitable denial-of-service vulnerability exists in the Linux kernel prior to mainline 5.3. An
    attacker could exploit this vulnerability by triggering AP to send IAPP location updates for stations
    before the required authentication process has completed. This could lead to different denial-of-service
    scenarios, either by causing CAM table attacks, or by leading to traffic flapping if faking already
    existing clients in other nearby APs of the same wireless infrastructure. An attacker can forge
    Authentication and Association Request packets to trigger this vulnerability. (CVE-2019-5108)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0098");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-19824");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-15214");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-15927");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-5108");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15927");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-abi-whitelists");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-sign-keys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-sign-keys");
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
    'kernel-3.10.0-693.21.1.el7.cgslv5_4.56.930.g7d1961c.lite',
    'kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5_4.56.930.g7d1961c.lite',
    'kernel-core-3.10.0-693.21.1.el7.cgslv5_4.56.930.g7d1961c.lite',
    'kernel-debug-core-3.10.0-693.21.1.el7.cgslv5_4.56.930.g7d1961c.lite',
    'kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.56.930.g7d1961c.lite',
    'kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5_4.56.930.g7d1961c.lite',
    'kernel-debug-modules-3.10.0-693.21.1.el7.cgslv5_4.56.930.g7d1961c.lite',
    'kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.56.930.g7d1961c.lite',
    'kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5_4.56.930.g7d1961c.lite',
    'kernel-devel-3.10.0-693.21.1.el7.cgslv5_4.56.930.g7d1961c.lite',
    'kernel-headers-3.10.0-693.21.1.el7.cgslv5_4.56.930.g7d1961c.lite',
    'kernel-modules-3.10.0-693.21.1.el7.cgslv5_4.56.930.g7d1961c.lite',
    'kernel-sign-keys-3.10.0-693.21.1.el7.cgslv5_4.56.930.g7d1961c.lite',
    'kernel-tools-3.10.0-693.21.1.el7.cgslv5_4.56.930.g7d1961c.lite',
    'kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.56.930.g7d1961c.lite',
    'kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5_4.56.930.g7d1961c.lite',
    'kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5_4.56.930.g7d1961c.lite',
    'perf-3.10.0-693.21.1.el7.cgslv5_4.56.930.g7d1961c.lite',
    'perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.56.930.g7d1961c.lite',
    'python-perf-3.10.0-693.21.1.el7.cgslv5_4.56.930.g7d1961c.lite',
    'python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.56.930.g7d1961c.lite'
  ],
  'CGSL MAIN 5.04': [
    'kernel-3.10.0-693.21.1.el7.cgslv5_4.55.989.g6f28a5a',
    'kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5_4.55.989.g6f28a5a',
    'kernel-debug-3.10.0-693.21.1.el7.cgslv5_4.55.989.g6f28a5a',
    'kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.55.989.g6f28a5a',
    'kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5_4.55.989.g6f28a5a',
    'kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.55.989.g6f28a5a',
    'kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5_4.55.989.g6f28a5a',
    'kernel-devel-3.10.0-693.21.1.el7.cgslv5_4.55.989.g6f28a5a',
    'kernel-headers-3.10.0-693.21.1.el7.cgslv5_4.55.989.g6f28a5a',
    'kernel-sign-keys-3.10.0-693.21.1.el7.cgslv5_4.55.989.g6f28a5a',
    'kernel-tools-3.10.0-693.21.1.el7.cgslv5_4.55.989.g6f28a5a',
    'kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.55.989.g6f28a5a',
    'kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5_4.55.989.g6f28a5a',
    'kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5_4.55.989.g6f28a5a',
    'perf-3.10.0-693.21.1.el7.cgslv5_4.55.989.g6f28a5a',
    'perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.55.989.g6f28a5a',
    'python-perf-3.10.0-693.21.1.el7.cgslv5_4.55.989.g6f28a5a',
    'python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.55.989.g6f28a5a'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel');
}
