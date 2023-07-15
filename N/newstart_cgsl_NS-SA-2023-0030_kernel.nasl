#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2023-0030. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174055);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/11");

  script_cve_id(
    "CVE-2022-1012",
    "CVE-2022-3542",
    "CVE-2022-3586",
    "CVE-2022-3594",
    "CVE-2022-41850",
    "CVE-2022-43750"
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : kernel Multiple Vulnerabilities (NS-SA-2023-0030)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has kernel packages installed that are affected by
multiple vulnerabilities:

  - A memory leak problem was found in the TCP source port generation algorithm in net/ipv4/tcp.c due to the
    small table perturb size. This flaw may allow an attacker to information leak and may cause a denial of
    service problem. (CVE-2022-1012)

  - A flaw was found in the Linux kernel's networking code. A use-after-free was found in the way the sch_sfb
    enqueue function used the socket buffer (SKB) cb field after the same SKB had been enqueued (and freed)
    into a child qdisc. This flaw allows a local, unprivileged user to crash the system, causing a denial of
    service. (CVE-2022-3586)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. Affected by this
    vulnerability is the function intr_callback of the file drivers/net/usb/r8152.c of the component BPF. The
    manipulation leads to logging of excessive data. The attack can be launched remotely. It is recommended to
    apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-211363.
    (CVE-2022-3594)

  - roccat_report_event in drivers/hid/hid-roccat.c in the Linux kernel through 5.19.12 has a race condition
    and resultant use-after-free in certain situations where a report is received while copying a
    report->value is in progress. (CVE-2022-41850)

  - drivers/usb/mon/mon_bin.c in usbmon in the Linux kernel before 5.19.15 and 6.x before 6.0.1 allows a user-
    space client to corrupt the monitor's internal memory. (CVE-2022-43750)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2023-0030");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-1012");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-3542");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-3586");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-3594");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-41850");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-43750");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1012");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/11");

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
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'kernel-3.10.0-693.21.1.el7.cgslv5_4.57.1097.gc3d92d8.lite',
    'kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5_4.57.1097.gc3d92d8.lite',
    'kernel-core-3.10.0-693.21.1.el7.cgslv5_4.57.1097.gc3d92d8.lite',
    'kernel-debug-core-3.10.0-693.21.1.el7.cgslv5_4.57.1097.gc3d92d8.lite',
    'kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.57.1097.gc3d92d8.lite',
    'kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5_4.57.1097.gc3d92d8.lite',
    'kernel-debug-modules-3.10.0-693.21.1.el7.cgslv5_4.57.1097.gc3d92d8.lite',
    'kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.57.1097.gc3d92d8.lite',
    'kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5_4.57.1097.gc3d92d8.lite',
    'kernel-devel-3.10.0-693.21.1.el7.cgslv5_4.57.1097.gc3d92d8.lite',
    'kernel-headers-3.10.0-693.21.1.el7.cgslv5_4.57.1097.gc3d92d8.lite',
    'kernel-modules-3.10.0-693.21.1.el7.cgslv5_4.57.1097.gc3d92d8.lite',
    'kernel-sign-keys-3.10.0-693.21.1.el7.cgslv5_4.57.1097.gc3d92d8.lite',
    'kernel-tools-3.10.0-693.21.1.el7.cgslv5_4.57.1097.gc3d92d8.lite',
    'kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.57.1097.gc3d92d8.lite',
    'kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5_4.57.1097.gc3d92d8.lite',
    'kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5_4.57.1097.gc3d92d8.lite',
    'perf-3.10.0-693.21.1.el7.cgslv5_4.57.1097.gc3d92d8.lite',
    'perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.57.1097.gc3d92d8.lite',
    'python-perf-3.10.0-693.21.1.el7.cgslv5_4.57.1097.gc3d92d8.lite',
    'python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.57.1097.gc3d92d8.lite'
  ],
  'CGSL MAIN 5.04': [
    'kernel-3.10.0-693.21.1.el7.cgslv5_4.55.1191.gec1c275',
    'kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5_4.55.1191.gec1c275',
    'kernel-debug-3.10.0-693.21.1.el7.cgslv5_4.55.1191.gec1c275',
    'kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.55.1191.gec1c275',
    'kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5_4.55.1191.gec1c275',
    'kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.55.1191.gec1c275',
    'kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5_4.55.1191.gec1c275',
    'kernel-devel-3.10.0-693.21.1.el7.cgslv5_4.55.1191.gec1c275',
    'kernel-headers-3.10.0-693.21.1.el7.cgslv5_4.55.1191.gec1c275',
    'kernel-sign-keys-3.10.0-693.21.1.el7.cgslv5_4.55.1191.gec1c275',
    'kernel-tools-3.10.0-693.21.1.el7.cgslv5_4.55.1191.gec1c275',
    'kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.55.1191.gec1c275',
    'kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5_4.55.1191.gec1c275',
    'kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5_4.55.1191.gec1c275',
    'perf-3.10.0-693.21.1.el7.cgslv5_4.55.1191.gec1c275',
    'perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.55.1191.gec1c275',
    'python-perf-3.10.0-693.21.1.el7.cgslv5_4.55.1191.gec1c275',
    'python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.55.1191.gec1c275'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel');
}
