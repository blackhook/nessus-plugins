#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0002. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133072);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2018-12207",
    "CVE-2019-0154",
    "CVE-2019-0155",
    "CVE-2019-9500",
    "CVE-2019-11135"
  );
  script_bugtraq_id(108011);

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : kernel Multiple Vulnerabilities (NS-SA-2020-0002)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has kernel packages installed that are affected by
multiple vulnerabilities:

  - Improper invalidation for page table updates by a
    virtual guest operating system for multiple Intel(R)
    Processors may allow an authenticated user to
    potentially enable denial of service of the host system
    via local access. (CVE-2018-12207)

  - Insufficient access control in subsystem for Intel (R)
    processor graphics in 6th, 7th, 8th and 9th Generation
    Intel(R) Core(TM) Processor Families; Intel(R)
    Pentium(R) Processor J, N, Silver and Gold Series;
    Intel(R) Celeron(R) Processor J, N, G3900 and G4900
    Series; Intel(R) Atom(R) Processor A and E3900 Series;
    Intel(R) Xeon(R) Processor E3-1500 v5 and v6 and E-2100
    Processor Families may allow an authenticated user to
    potentially enable denial of service via local access.
    (CVE-2019-0154)

  - Insufficient access control in a subsystem for Intel (R)
    processor graphics in 6th, 7th, 8th and 9th Generation
    Intel(R) Core(TM) Processor Families; Intel(R)
    Pentium(R) Processor J, N, Silver and Gold Series;
    Intel(R) Celeron(R) Processor J, N, G3900 and G4900
    Series; Intel(R) Atom(R) Processor A and E3900 Series;
    Intel(R) Xeon(R) Processor E3-1500 v5 and v6, E-2100 and
    E-2200 Processor Families; Intel(R) Graphics Driver for
    Windows before 26.20.100.6813 (DCH) or 26.20.100.6812
    and before 21.20.x.5077 (aka15.45.5077), i915 Linux
    Driver for Intel(R) Processor Graphics before versions
    5.4-rc7, 5.3.11, 4.19.84, 4.14.154, 4.9.201, 4.4.201 may
    allow an authenticated user to potentially enable
    escalation of privilege via local access.
    (CVE-2019-0155)

  - TSX Asynchronous Abort condition on some CPUs utilizing
    speculative execution may allow an authenticated user to
    potentially enable information disclosure via a side
    channel with local access. (CVE-2019-11135)

  - The Broadcom brcmfmac WiFi driver prior to commit
    1b5e2423164b3670e8bc9174e4762d297990deff is vulnerable
    to a heap buffer overflow. If the Wake-up on Wireless
    LAN functionality is configured, a malicious event frame
    can be constructed to trigger an heap buffer overflow in
    the brcmf_wowl_nd_results function. This vulnerability
    can be exploited with compromised chipsets to compromise
    the host, or when used in combination with
    CVE-2019-9503, can be used remotely. In the worst case
    scenario, by sending specially-crafted WiFi packets, a
    remote, unauthenticated attacker may be able to execute
    arbitrary code on a vulnerable system. More typically,
    this vulnerability will result in denial-of-service
    conditions. (CVE-2019-9500)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0002");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9500");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/20");

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

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.05": [
    "bpftool-3.10.0-957.27.2.el7.cgslv5_5.15.158.gb9eb45c.lite",
    "kernel-3.10.0-957.27.2.el7.cgslv5_5.15.158.gb9eb45c.lite",
    "kernel-abi-whitelists-3.10.0-957.27.2.el7.cgslv5_5.15.158.gb9eb45c.lite",
    "kernel-core-3.10.0-957.27.2.el7.cgslv5_5.15.158.gb9eb45c.lite",
    "kernel-debug-core-3.10.0-957.27.2.el7.cgslv5_5.15.158.gb9eb45c.lite",
    "kernel-debug-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.15.158.gb9eb45c.lite",
    "kernel-debug-devel-3.10.0-957.27.2.el7.cgslv5_5.15.158.gb9eb45c.lite",
    "kernel-debug-modules-3.10.0-957.27.2.el7.cgslv5_5.15.158.gb9eb45c.lite",
    "kernel-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.15.158.gb9eb45c.lite",
    "kernel-debuginfo-common-x86_64-3.10.0-957.27.2.el7.cgslv5_5.15.158.gb9eb45c.lite",
    "kernel-devel-3.10.0-957.27.2.el7.cgslv5_5.15.158.gb9eb45c.lite",
    "kernel-headers-3.10.0-957.27.2.el7.cgslv5_5.15.158.gb9eb45c.lite",
    "kernel-modules-3.10.0-957.27.2.el7.cgslv5_5.15.158.gb9eb45c.lite",
    "kernel-tools-3.10.0-957.27.2.el7.cgslv5_5.15.158.gb9eb45c.lite",
    "kernel-tools-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.15.158.gb9eb45c.lite",
    "kernel-tools-libs-3.10.0-957.27.2.el7.cgslv5_5.15.158.gb9eb45c.lite",
    "kernel-tools-libs-devel-3.10.0-957.27.2.el7.cgslv5_5.15.158.gb9eb45c.lite",
    "perf-3.10.0-957.27.2.el7.cgslv5_5.15.158.gb9eb45c.lite",
    "perf-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.15.158.gb9eb45c.lite",
    "python-perf-3.10.0-957.27.2.el7.cgslv5_5.15.158.gb9eb45c.lite",
    "python-perf-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.15.158.gb9eb45c.lite"
  ],
  "CGSL MAIN 5.05": [
    "bpftool-3.10.0-957.27.2.el7.cgslv5_5.15.155.g618e202",
    "kernel-3.10.0-957.27.2.el7.cgslv5_5.15.155.g618e202",
    "kernel-abi-whitelists-3.10.0-957.27.2.el7.cgslv5_5.15.155.g618e202",
    "kernel-debug-3.10.0-957.27.2.el7.cgslv5_5.15.155.g618e202",
    "kernel-debug-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.15.155.g618e202",
    "kernel-debug-devel-3.10.0-957.27.2.el7.cgslv5_5.15.155.g618e202",
    "kernel-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.15.155.g618e202",
    "kernel-debuginfo-common-x86_64-3.10.0-957.27.2.el7.cgslv5_5.15.155.g618e202",
    "kernel-devel-3.10.0-957.27.2.el7.cgslv5_5.15.155.g618e202",
    "kernel-headers-3.10.0-957.27.2.el7.cgslv5_5.15.155.g618e202",
    "kernel-tools-3.10.0-957.27.2.el7.cgslv5_5.15.155.g618e202",
    "kernel-tools-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.15.155.g618e202",
    "kernel-tools-libs-3.10.0-957.27.2.el7.cgslv5_5.15.155.g618e202",
    "kernel-tools-libs-devel-3.10.0-957.27.2.el7.cgslv5_5.15.155.g618e202",
    "perf-3.10.0-957.27.2.el7.cgslv5_5.15.155.g618e202",
    "perf-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.15.155.g618e202",
    "python-perf-3.10.0-957.27.2.el7.cgslv5_5.15.155.g618e202",
    "python-perf-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.15.155.g618e202"
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
