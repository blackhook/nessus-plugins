#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0221. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131411);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2018-20856",
    "CVE-2019-3846",
    "CVE-2019-9500",
    "CVE-2019-9503",
    "CVE-2019-9506",
    "CVE-2019-10126",
    "CVE-2019-10140"
  );
  script_bugtraq_id(108011, 108521, 108817);

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : kernel Multiple Vulnerabilities (NS-SA-2019-0221)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has kernel packages installed that are affected by
multiple vulnerabilities:

  - An issue was discovered in the Linux kernel before
    4.18.7. In block/blk-core.c, there is an
    __blk_drain_queue() use-after-free because a certain
    error case is mishandled. (CVE-2018-20856)

  - A flaw was found in the Linux kernel. A heap based
    buffer overflow in mwifiex_uap_parse_tail_ies function
    in drivers/net/wireless/marvell/mwifiex/ie.c might lead
    to memory corruption and possibly other consequences.
    (CVE-2019-10126)

  - A vulnerability was found in Linux kernel's, versions up
    to 3.10, implementation of overlayfs. An attacker with
    local access can create a denial of service situation
    via NULL pointer dereference in ovl_posix_acl_create
    function in fs/overlayfs/dir.c. This can allow attackers
    with ability to create directories on overlayfs to crash
    the kernel creating a denial of service (DOS).
    (CVE-2019-10140)

  - A flaw that allowed an attacker to corrupt memory and
    possibly escalate privileges was found in the mwifiex
    kernel module while connecting to a malicious wireless
    network. (CVE-2019-3846)

  - The Bluetooth BR/EDR specification up to and including
    version 5.1 permits sufficiently low encryption key
    length and does not prevent an attacker from influencing
    the key length negotiation. This allows practical brute-
    force attacks (aka KNOB) that can decrypt traffic and
    inject arbitrary ciphertext without the victim noticing.
    (CVE-2019-9506)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0221");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3846");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-10126");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    "kernel-3.10.0-693.21.1.el7.cgslv5_4.26.523.g01e5e7b.lite",
    "kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5_4.26.523.g01e5e7b.lite",
    "kernel-core-3.10.0-693.21.1.el7.cgslv5_4.26.523.g01e5e7b.lite",
    "kernel-debug-core-3.10.0-693.21.1.el7.cgslv5_4.26.523.g01e5e7b.lite",
    "kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.26.523.g01e5e7b.lite",
    "kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5_4.26.523.g01e5e7b.lite",
    "kernel-debug-modules-3.10.0-693.21.1.el7.cgslv5_4.26.523.g01e5e7b.lite",
    "kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.26.523.g01e5e7b.lite",
    "kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5_4.26.523.g01e5e7b.lite",
    "kernel-devel-3.10.0-693.21.1.el7.cgslv5_4.26.523.g01e5e7b.lite",
    "kernel-doc-3.10.0-693.21.1.el7.cgslv5_4.26.523.g01e5e7b.lite",
    "kernel-headers-3.10.0-693.21.1.el7.cgslv5_4.26.523.g01e5e7b.lite",
    "kernel-modules-3.10.0-693.21.1.el7.cgslv5_4.26.523.g01e5e7b.lite",
    "kernel-sign-keys-3.10.0-693.21.1.el7.cgslv5_4.26.523.g01e5e7b.lite",
    "kernel-tools-3.10.0-693.21.1.el7.cgslv5_4.26.523.g01e5e7b.lite",
    "kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.26.523.g01e5e7b.lite",
    "kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5_4.26.523.g01e5e7b.lite",
    "kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5_4.26.523.g01e5e7b.lite",
    "perf-3.10.0-693.21.1.el7.cgslv5_4.26.523.g01e5e7b.lite",
    "perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.26.523.g01e5e7b.lite",
    "python-perf-3.10.0-693.21.1.el7.cgslv5_4.26.523.g01e5e7b.lite",
    "python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.26.523.g01e5e7b.lite"
  ],
  "CGSL MAIN 5.04": [
    "kernel-3.10.0-693.21.1.el7.cgslv5_4.26.520.g15f3a85",
    "kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5_4.26.520.g15f3a85",
    "kernel-debug-3.10.0-693.21.1.el7.cgslv5_4.26.520.g15f3a85",
    "kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.26.520.g15f3a85",
    "kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5_4.26.520.g15f3a85",
    "kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.26.520.g15f3a85",
    "kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5_4.26.520.g15f3a85",
    "kernel-devel-3.10.0-693.21.1.el7.cgslv5_4.26.520.g15f3a85",
    "kernel-doc-3.10.0-693.21.1.el7.cgslv5_4.26.520.g15f3a85",
    "kernel-headers-3.10.0-693.21.1.el7.cgslv5_4.26.520.g15f3a85",
    "kernel-sign-keys-3.10.0-693.21.1.el7.cgslv5_4.26.520.g15f3a85",
    "kernel-tools-3.10.0-693.21.1.el7.cgslv5_4.26.520.g15f3a85",
    "kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.26.520.g15f3a85",
    "kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5_4.26.520.g15f3a85",
    "kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5_4.26.520.g15f3a85",
    "perf-3.10.0-693.21.1.el7.cgslv5_4.26.520.g15f3a85",
    "perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.26.520.g15f3a85",
    "python-perf-3.10.0-693.21.1.el7.cgslv5_4.26.520.g15f3a85",
    "python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.26.520.g15f3a85"
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
