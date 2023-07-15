#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0014. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127165);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2015-8539",
    "CVE-2017-7472",
    "CVE-2017-7518",
    "CVE-2017-12188",
    "CVE-2017-12192",
    "CVE-2017-12193",
    "CVE-2017-15649"
  );

  script_name(english:"NewStart CGSL MAIN 5.04 : kernel Multiple Vulnerabilities (NS-SA-2019-0014)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 5.04, has kernel packages installed that are affected by multiple
vulnerabilities:

  - A flaw was found in the Linux kernel's key management
    system where it was possible for an attacker to escalate
    privileges or crash the machine. If a user key gets
    negatively instantiated, an error code is cached in the
    payload area. A negatively instantiated key may be then
    be positively instantiated by updating it with valid
    data. However, the ->update key type method must be
    aware that the error code may be there. (CVE-2015-8539)

  - A flaw was found in the way the Linux KVM module
    processed the trap flag(TF) bit in EFLAGS during
    emulation of the syscall instruction, which leads to a
    debug exception(#DB) being raised in the guest stack. A
    user/process inside a guest could use this flaw to
    potentially escalate their privileges inside the guest.
    Linux guests are not affected by this. (CVE-2017-7518)

  - A vulnerability was found in the Key Management sub
    component of the Linux kernel, where when trying to
    issue a KEYTCL_READ on a negative key would lead to a
    NULL pointer dereference. A local attacker could use
    this flaw to crash the kernel. (CVE-2017-12192)

  - The Linux kernel built with the KVM visualization
    support (CONFIG_KVM), with nested visualization(nVMX)
    feature enabled (nested=1), was vulnerable to a stack
    buffer overflow issue. The vulnerability could occur
    while traversing guest page table entries to resolve
    guest virtual address(gva). An L1 guest could use this
    flaw to crash the host kernel resulting in denial of
    service (DoS) or potentially execute arbitrary code on
    the host to gain privileges on the system.
    (CVE-2017-12188)

  - A flaw was found in the Linux kernel's implementation of
    associative arrays introduced in 3.13. This
    functionality was backported to the 3.10 kernels in Red
    Hat Enterprise Linux 7. The flaw involved a null pointer
    dereference in assoc_array_apply_edit() due to incorrect
    node-splitting in assoc_array implementation. This
    affects the keyring key type and thus key addition and
    link creation operations may cause the kernel to panic.
    (CVE-2017-12193)

  - It was found that fanout_add() in
    'net/packet/af_packet.c' in the Linux kernel, before
    version 4.13.6, allows local users to gain privileges
    via crafted system calls that trigger mishandling of
    packet_fanout data structures, because of a race
    condition (involving fanout_add and packet_do_bind) that
    leads to a use-after-free bug. (CVE-2017-15649)

  - A vulnerability was found in the Linux kernel where the
    keyctl_set_reqkey_keyring() function leaks the thread
    keyring. This allows an unprivileged local user to
    exhaust kernel memory and thus cause a DoS.
    (CVE-2017-7472)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0014");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-8539");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/08");
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

if (release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 5.04": [
    "kernel-3.10.0-693.21.1.el7.cgslv5u4.0.38.g13ce111",
    "kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5u4.0.38.g13ce111",
    "kernel-debug-3.10.0-693.21.1.el7.cgslv5u4.0.38.g13ce111",
    "kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5u4.0.38.g13ce111",
    "kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5u4.0.38.g13ce111",
    "kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5u4.0.38.g13ce111",
    "kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5u4.0.38.g13ce111",
    "kernel-devel-3.10.0-693.21.1.el7.cgslv5u4.0.38.g13ce111",
    "kernel-doc-3.10.0-693.21.1.el7.cgslv5u4.0.38.g13ce111",
    "kernel-headers-3.10.0-693.21.1.el7.cgslv5u4.0.38.g13ce111",
    "kernel-tools-3.10.0-693.21.1.el7.cgslv5u4.0.38.g13ce111",
    "kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5u4.0.38.g13ce111",
    "kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5u4.0.38.g13ce111",
    "kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5u4.0.38.g13ce111",
    "perf-3.10.0-693.21.1.el7.cgslv5u4.0.38.g13ce111",
    "perf-debuginfo-3.10.0-693.21.1.el7.cgslv5u4.0.38.g13ce111",
    "python-perf-3.10.0-693.21.1.el7.cgslv5u4.0.38.g13ce111",
    "python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5u4.0.38.g13ce111"
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
