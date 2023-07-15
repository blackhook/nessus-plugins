#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#


# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0200. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129924);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2019-1125", "CVE-2019-14821", "CVE-2019-14835");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : kernel Multiple Vulnerabilities (NS-SA-2019-0200)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has kernel packages installed that are affected by
multiple vulnerabilities:

  - An information disclosure vulnerability exists when
    certain central processing units (CPU) speculatively
    access memory, aka 'Windows Kernel Information
    Disclosure Vulnerability'. This CVE ID is unique from
    CVE-2019-1071, CVE-2019-1073. (CVE-2019-1125)

  - An out-of-bounds access issue was found in the Linux
    kernel, all versions through 5.3, in the way Linux
    kernel's KVM hypervisor implements the Coalesced MMIO
    write operation. It operates on an MMIO ring buffer
    'struct kvm_coalesced_mmio' object, wherein write
    indices 'ring->first' and 'ring->last' value could be
    supplied by a host user-space process. An unprivileged
    host user or process with access to '/dev/kvm' device
    could use this flaw to crash the host kernel, resulting
    in a denial of service or potentially escalating
    privileges on the system. (CVE-2019-14821)

  - A buffer overflow flaw was found, in versions from
    2.6.34 to 5.2.x, in the way Linux kernel's vhost
    functionality that translates virtqueue buffers to IOVs,
    logged the buffer descriptors during migration. A
    privileged guest user able to pass descriptors with
    invalid length to the host when migration is underway,
    could use this flaw to increase their privileges on the
    host. (CVE-2019-14835)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0200");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14835");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-14821");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/15");

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
    "kernel-3.10.0-693.21.1.el7.cgslv5_4.22.462.gc02854e.lite",
    "kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5_4.22.462.gc02854e.lite",
    "kernel-core-3.10.0-693.21.1.el7.cgslv5_4.22.462.gc02854e.lite",
    "kernel-debug-core-3.10.0-693.21.1.el7.cgslv5_4.22.462.gc02854e.lite",
    "kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.22.462.gc02854e.lite",
    "kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5_4.22.462.gc02854e.lite",
    "kernel-debug-modules-3.10.0-693.21.1.el7.cgslv5_4.22.462.gc02854e.lite",
    "kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.22.462.gc02854e.lite",
    "kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5_4.22.462.gc02854e.lite",
    "kernel-devel-3.10.0-693.21.1.el7.cgslv5_4.22.462.gc02854e.lite",
    "kernel-doc-3.10.0-693.21.1.el7.cgslv5_4.22.462.gc02854e.lite",
    "kernel-headers-3.10.0-693.21.1.el7.cgslv5_4.22.462.gc02854e.lite",
    "kernel-modules-3.10.0-693.21.1.el7.cgslv5_4.22.462.gc02854e.lite",
    "kernel-sign-keys-3.10.0-693.21.1.el7.cgslv5_4.22.462.gc02854e.lite",
    "kernel-tools-3.10.0-693.21.1.el7.cgslv5_4.22.462.gc02854e.lite",
    "kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.22.462.gc02854e.lite",
    "kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5_4.22.462.gc02854e.lite",
    "kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5_4.22.462.gc02854e.lite",
    "perf-3.10.0-693.21.1.el7.cgslv5_4.22.462.gc02854e.lite",
    "perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.22.462.gc02854e.lite",
    "python-perf-3.10.0-693.21.1.el7.cgslv5_4.22.462.gc02854e.lite",
    "python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.22.462.gc02854e.lite"
  ],
  "CGSL MAIN 5.04": [
    "kernel-3.10.0-693.21.1.el7.cgslv5_4.22.459.gdcac6d6",
    "kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5_4.22.459.gdcac6d6",
    "kernel-debug-3.10.0-693.21.1.el7.cgslv5_4.22.459.gdcac6d6",
    "kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.22.459.gdcac6d6",
    "kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5_4.22.459.gdcac6d6",
    "kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.22.459.gdcac6d6",
    "kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5_4.22.459.gdcac6d6",
    "kernel-devel-3.10.0-693.21.1.el7.cgslv5_4.22.459.gdcac6d6",
    "kernel-doc-3.10.0-693.21.1.el7.cgslv5_4.22.459.gdcac6d6",
    "kernel-headers-3.10.0-693.21.1.el7.cgslv5_4.22.459.gdcac6d6",
    "kernel-sign-keys-3.10.0-693.21.1.el7.cgslv5_4.22.459.gdcac6d6",
    "kernel-tools-3.10.0-693.21.1.el7.cgslv5_4.22.459.gdcac6d6",
    "kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.22.459.gdcac6d6",
    "kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5_4.22.459.gdcac6d6",
    "kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5_4.22.459.gdcac6d6",
    "perf-3.10.0-693.21.1.el7.cgslv5_4.22.459.gdcac6d6",
    "perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.22.459.gdcac6d6",
    "python-perf-3.10.0-693.21.1.el7.cgslv5_4.22.459.gdcac6d6",
    "python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.22.459.gdcac6d6"
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
