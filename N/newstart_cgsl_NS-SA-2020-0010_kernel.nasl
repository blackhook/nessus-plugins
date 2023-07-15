#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#


# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0010. The text
# itself is copyright (C) ZTE, Inc.


include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134320);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2019-14816",
    "CVE-2019-14895",
    "CVE-2019-14898",
    "CVE-2019-14901",
    "CVE-2019-17133"
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : kernel Multiple Vulnerabilities (NS-SA-2020-0010)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has kernel packages installed that are affected by
multiple vulnerabilities:

  - There is heap-based buffer overflow in kernel, all
    versions up to, excluding 5.3, in the marvell wifi chip
    driver in Linux kernel, that allows local users to cause
    a denial of service(system crash) or possibly execute
    arbitrary code. (CVE-2019-14816)

  - A heap-based buffer overflow was discovered in the Linux
    kernel, all versions 3.x.x and 4.x.x before 4.18.0, in
    Marvell WiFi chip driver. The flaw could occur when the
    station attempts a connection negotiation during the
    handling of the remote devices country settings. This
    could allow the remote device to cause a denial of
    service (system crash) or possibly execute arbitrary
    code. (CVE-2019-14895)

  - A heap overflow flaw was found in the Linux kernel, all
    versions 3.x.x and 4.x.x before 4.18.0, in Marvell WiFi
    chip driver. The vulnerability allows a remote attacker
    to cause a system crash, resulting in a denial of
    service, or execute arbitrary code. The highest threat
    with this vulnerability is with the availability of the
    system. If code execution occurs, the code will run with
    the permissions of root. This will affect both
    confidentiality and integrity of files on the system.
    (CVE-2019-14901)

  - In the Linux kernel through 5.3.2,
    cfg80211_mgd_wext_giwessid in net/wireless/wext-sme.c
    does not reject a long SSID IE, leading to a Buffer
    Overflow. (CVE-2019-17133)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0010");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14901");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "kernel-3.10.0-693.21.1.el7.cgslv5_4.34.569.gabd82ea.lite",
    "kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5_4.34.569.gabd82ea.lite",
    "kernel-core-3.10.0-693.21.1.el7.cgslv5_4.34.569.gabd82ea.lite",
    "kernel-debug-core-3.10.0-693.21.1.el7.cgslv5_4.34.569.gabd82ea.lite",
    "kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.34.569.gabd82ea.lite",
    "kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5_4.34.569.gabd82ea.lite",
    "kernel-debug-modules-3.10.0-693.21.1.el7.cgslv5_4.34.569.gabd82ea.lite",
    "kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.34.569.gabd82ea.lite",
    "kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5_4.34.569.gabd82ea.lite",
    "kernel-devel-3.10.0-693.21.1.el7.cgslv5_4.34.569.gabd82ea.lite",
    "kernel-headers-3.10.0-693.21.1.el7.cgslv5_4.34.569.gabd82ea.lite",
    "kernel-modules-3.10.0-693.21.1.el7.cgslv5_4.34.569.gabd82ea.lite",
    "kernel-sign-keys-3.10.0-693.21.1.el7.cgslv5_4.34.569.gabd82ea.lite",
    "kernel-tools-3.10.0-693.21.1.el7.cgslv5_4.34.569.gabd82ea.lite",
    "kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.34.569.gabd82ea.lite",
    "kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5_4.34.569.gabd82ea.lite",
    "kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5_4.34.569.gabd82ea.lite",
    "perf-3.10.0-693.21.1.el7.cgslv5_4.34.569.gabd82ea.lite",
    "perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.34.569.gabd82ea.lite",
    "python-perf-3.10.0-693.21.1.el7.cgslv5_4.34.569.gabd82ea.lite",
    "python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.34.569.gabd82ea.lite"
  ],
  "CGSL MAIN 5.04": [
    "kernel-3.10.0-693.21.1.el7.cgslv5_4.34.565.g2ffb389",
    "kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5_4.34.565.g2ffb389",
    "kernel-debug-3.10.0-693.21.1.el7.cgslv5_4.34.565.g2ffb389",
    "kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.34.565.g2ffb389",
    "kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5_4.34.565.g2ffb389",
    "kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.34.565.g2ffb389",
    "kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5_4.34.565.g2ffb389",
    "kernel-devel-3.10.0-693.21.1.el7.cgslv5_4.34.565.g2ffb389",
    "kernel-headers-3.10.0-693.21.1.el7.cgslv5_4.34.565.g2ffb389",
    "kernel-sign-keys-3.10.0-693.21.1.el7.cgslv5_4.34.565.g2ffb389",
    "kernel-tools-3.10.0-693.21.1.el7.cgslv5_4.34.565.g2ffb389",
    "kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.34.565.g2ffb389",
    "kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5_4.34.565.g2ffb389",
    "kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5_4.34.565.g2ffb389",
    "perf-3.10.0-693.21.1.el7.cgslv5_4.34.565.g2ffb389",
    "perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.34.565.g2ffb389",
    "python-perf-3.10.0-693.21.1.el7.cgslv5_4.34.565.g2ffb389",
    "python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.34.565.g2ffb389"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
