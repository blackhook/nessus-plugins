#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0034. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127202);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2017-1000365", "CVE-2018-5390", "CVE-2018-14634");
  script_bugtraq_id(104976, 105407);

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : kernel Multiple Vulnerabilities (NS-SA-2019-0034)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has kernel packages installed that are affected by
multiple vulnerabilities:

  - The Linux Kernel imposes a size restriction on the
    arguments and environmental strings passed through
    RLIMIT_STACK/RLIMIT_INFINITY, but does not take the
    argument and environment pointers into account, which
    allows attackers to bypass this limitation.
    (CVE-2017-1000365)

  - An integer overflow flaw was found in the Linux kernel's
    create_elf_tables() function. An unprivileged local user
    with access to SUID (or otherwise privileged) binary
    could use this flaw to escalate their privileges on the
    system. (CVE-2018-14634)

  - A flaw named SegmentSmack was found in the way the Linux
    kernel handled specially crafted TCP packets. A remote
    attacker could use this flaw to trigger time and
    calculation expensive calls to tcp_collapse_ofo_queue()
    and tcp_prune_ofo_queue() functions by sending specially
    modified packets within ongoing TCP sessions which could
    lead to a CPU saturation and hence a denial of service
    on the system. Maintaining the denial of service
    condition requires continuous two-way TCP sessions to a
    reachable open port, thus the attacks cannot be
    performed using spoofed IP addresses. (CVE-2018-5390)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0034");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14634");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    "kernel-3.10.0-693.21.1.el7.cgslv5u4lite.7.159.gd430b7b",
    "kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5u4lite.7.159.gd430b7b",
    "kernel-core-3.10.0-693.21.1.el7.cgslv5u4lite.7.159.gd430b7b",
    "kernel-debug-core-3.10.0-693.21.1.el7.cgslv5u4lite.7.159.gd430b7b",
    "kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5u4lite.7.159.gd430b7b",
    "kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5u4lite.7.159.gd430b7b",
    "kernel-debug-modules-3.10.0-693.21.1.el7.cgslv5u4lite.7.159.gd430b7b",
    "kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5u4lite.7.159.gd430b7b",
    "kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5u4lite.7.159.gd430b7b",
    "kernel-devel-3.10.0-693.21.1.el7.cgslv5u4lite.7.159.gd430b7b",
    "kernel-doc-3.10.0-693.21.1.el7.cgslv5u4lite.7.159.gd430b7b",
    "kernel-headers-3.10.0-693.21.1.el7.cgslv5u4lite.7.159.gd430b7b",
    "kernel-modules-3.10.0-693.21.1.el7.cgslv5u4lite.7.159.gd430b7b",
    "kernel-tools-3.10.0-693.21.1.el7.cgslv5u4lite.7.159.gd430b7b",
    "kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5u4lite.7.159.gd430b7b",
    "kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5u4lite.7.159.gd430b7b",
    "kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5u4lite.7.159.gd430b7b",
    "perf-3.10.0-693.21.1.el7.cgslv5u4lite.7.159.gd430b7b",
    "perf-debuginfo-3.10.0-693.21.1.el7.cgslv5u4lite.7.159.gd430b7b",
    "python-perf-3.10.0-693.21.1.el7.cgslv5u4lite.7.159.gd430b7b",
    "python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5u4lite.7.159.gd430b7b"
  ],
  "CGSL MAIN 5.04": [
    "kernel-3.10.0-693.21.1.el7.cgslv5u4.7.156.geedb421",
    "kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5u4.7.156.geedb421",
    "kernel-debug-3.10.0-693.21.1.el7.cgslv5u4.7.156.geedb421",
    "kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5u4.7.156.geedb421",
    "kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5u4.7.156.geedb421",
    "kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5u4.7.156.geedb421",
    "kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5u4.7.156.geedb421",
    "kernel-devel-3.10.0-693.21.1.el7.cgslv5u4.7.156.geedb421",
    "kernel-doc-3.10.0-693.21.1.el7.cgslv5u4.7.156.geedb421",
    "kernel-headers-3.10.0-693.21.1.el7.cgslv5u4.7.156.geedb421",
    "kernel-tools-3.10.0-693.21.1.el7.cgslv5u4.7.156.geedb421",
    "kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5u4.7.156.geedb421",
    "kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5u4.7.156.geedb421",
    "kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5u4.7.156.geedb421",
    "perf-3.10.0-693.21.1.el7.cgslv5u4.7.156.geedb421",
    "perf-debuginfo-3.10.0-693.21.1.el7.cgslv5u4.7.156.geedb421",
    "python-perf-3.10.0-693.21.1.el7.cgslv5u4.7.156.geedb421",
    "python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5u4.7.156.geedb421"
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
