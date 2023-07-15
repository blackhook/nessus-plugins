#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0028. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(136910);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2018-1087", "CVE-2018-10878", "CVE-2019-15239");
  script_bugtraq_id(104127, 104903);

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : kernel-rt Multiple Vulnerabilities (NS-SA-2020-0028)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has kernel-rt packages installed that are affected
by multiple vulnerabilities:

  - kernel KVM before versions kernel 4.16, kernel 4.16-rc7,
    kernel 4.17-rc1, kernel 4.17-rc2 and kernel 4.17-rc3 is
    vulnerable to a flaw in the way the Linux kernel's KVM
    hypervisor handled exceptions delivered after a stack
    switch operation via Mov SS or Pop SS instructions.
    During the stack switch operation, the processor did not
    deliver interrupts and exceptions, rather they are
    delivered once the first instruction after the stack
    switch is executed. An unprivileged KVM guest user could
    use this flaw to crash the guest or, potentially,
    escalate their privileges in the guest. (CVE-2018-1087)

  - A flaw was found in the Linux kernel's ext4 filesystem.
    A local user can cause an out-of-bounds write and a
    denial of service or unspecified other impact is
    possible by mounting and operating a crafted ext4
    filesystem image. (CVE-2018-10878)

  - In the Linux kernel, a certain net/ipv4/tcp_output.c
    change, which was properly incorporated into 4.16.12,
    was incorrectly backported to the earlier longterm
    kernels, introducing a new vulnerability that was
    potentially more severe than the issue that was intended
    to be fixed by backporting. Specifically, by adding to a
    write queue between disconnection and re-connection, a
    local attacker can trigger multiple use-after-free
    conditions. This can result in a kernel crash, or
    potentially in privilege escalation. NOTE: this affects
    (for example) Linux distributions that use 4.9.x
    longterm kernels before 4.9.190 or 4.14.x longterm
    kernels before 4.14.139. (CVE-2019-15239)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0028");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel-rt packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15239");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/27");

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
    "kernel-rt-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.32.418.g9ad7df6",
    "kernel-rt-debug-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.32.418.g9ad7df6",
    "kernel-rt-debug-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.32.418.g9ad7df6",
    "kernel-rt-debug-devel-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.32.418.g9ad7df6",
    "kernel-rt-debug-kvm-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.32.418.g9ad7df6",
    "kernel-rt-debug-kvm-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.32.418.g9ad7df6",
    "kernel-rt-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.32.418.g9ad7df6",
    "kernel-rt-debuginfo-common-x86_64-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.32.418.g9ad7df6",
    "kernel-rt-devel-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.32.418.g9ad7df6",
    "kernel-rt-doc-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.32.418.g9ad7df6",
    "kernel-rt-kvm-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.32.418.g9ad7df6",
    "kernel-rt-kvm-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.32.418.g9ad7df6",
    "kernel-rt-trace-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.32.418.g9ad7df6",
    "kernel-rt-trace-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.32.418.g9ad7df6",
    "kernel-rt-trace-devel-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.32.418.g9ad7df6",
    "kernel-rt-trace-kvm-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.32.418.g9ad7df6",
    "kernel-rt-trace-kvm-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.32.418.g9ad7df6"
  ],
  "CGSL MAIN 5.04": [
    "kernel-rt-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.32.418.g9ad7df6",
    "kernel-rt-debug-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.32.418.g9ad7df6",
    "kernel-rt-debug-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.32.418.g9ad7df6",
    "kernel-rt-debug-devel-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.32.418.g9ad7df6",
    "kernel-rt-debug-kvm-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.32.418.g9ad7df6",
    "kernel-rt-debug-kvm-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.32.418.g9ad7df6",
    "kernel-rt-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.32.418.g9ad7df6",
    "kernel-rt-debuginfo-common-x86_64-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.32.418.g9ad7df6",
    "kernel-rt-devel-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.32.418.g9ad7df6",
    "kernel-rt-doc-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.32.418.g9ad7df6",
    "kernel-rt-kvm-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.32.418.g9ad7df6",
    "kernel-rt-kvm-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.32.418.g9ad7df6",
    "kernel-rt-trace-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.32.418.g9ad7df6",
    "kernel-rt-trace-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.32.418.g9ad7df6",
    "kernel-rt-trace-devel-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.32.418.g9ad7df6",
    "kernel-rt-trace-kvm-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.32.418.g9ad7df6",
    "kernel-rt-trace-kvm-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.32.418.g9ad7df6"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-rt");
}
