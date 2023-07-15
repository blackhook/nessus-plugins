#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0116.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101195);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-8903", "CVE-2017-8904", "CVE-2017-8905");

  script_name(english:"OracleVM 3.4 : xen (OVMSA-2017-0116)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - BUILDINFO: xen
    commit=74b662e79bc874fe8ad8a93d2891e6569c380004

  - BUILDINFO: QEMU upstream
    commit=8bff6989bd0bafcc0ddf859c23ce6a2ff21a80ff

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - gnttab: __gnttab_unmap_common_complete is all-or-nothing
    (Jan Beulich) [Orabug: 26288614]

  - gnttab: correct logic to get page references during map
    requests (George Dunlap) [Orabug: 26288614]

  - gnttab: never create host mapping unless asked to (Jan
    Beulich) 

  - gnttab: Fix handling of dev_bus_addr during unmap
    (George Dunlap) 

  - x86/shadow: Hold references for the duration of emulated
    writes (Andrew Cooper) [Orabug: 26288568]

  - x86/mm: disallow page stealing from HVM domains (Jan
    Beulich) 

  - guest_physmap_remove_page needs its return value checked
    (Jan Beulich) [Orabug: 26288602]

  - xen/memory: Fix return value handing of
    guest_remove_page (Andrew Cooper) [Orabug: 26288602]

  - evtchn: avoid NULL derefs (Jan Beulich) [Orabug:
    26288583]

  - gnttab: correct maptrack table accesses (Jan Beulich)
    [Orabug: 26288557]

  - gnttab: Avoid potential double-put of maptrack entry
    (George Dunlap) 

  - gnttab: fix unmap pin accounting race (Jan Beulich)
    [Orabug: 26288557]

  - IOMMU: handle IOMMU mapping and unmapping failures (Quan
    Xu) [Orabug: 26288557]

  - xen/disk: don't leak stack data via response ring (Jan
    Beulich) 

  - BUILDINFO: xen
    commit=7b45c3eb48a884f56f072a97a9a8da4d0b1077ed

  - BUILDINFO: QEMU upstream
    commit=44c5f0a55d9a73e592426c33ce5705c969681955

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - livepatch: Wrong usage of spinlock on debug console.
    (Konrad Rzeszutek Wilk) [Orabug: 26248311]

  - BUILDINFO: xen
    commit=40e21e7aea2b8bbc991346c3f516dfac4f94affe

  - BUILDINFO: QEMU upstream
    commit=44c5f0a55d9a73e592426c33ce5705c969681955

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - x86/do_invalid_op should use is_active_kernel_text
    rather than having its (Konrad Rzeszutek Wilk) [Orabug:
    26129273]

  - BUILDINFO: xen
    commit=0eadc919cf32139e5565e0d869ed09f35c0a3212

  - BUILDINFO: QEMU upstream
    commit=44c5f0a55d9a73e592426c33ce5705c969681955

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - kexec: Add spinlock for the whole hypercall. (Konrad
    Rzeszutek Wilk) 

  - kexec: clear kexec_image slot when unloading kexec image
    (Bhavesh Davda) [Orabug: 25861742]

  - BUILDINFO: xen
    commit=8b90d66cd941599d50ee80e14fd144e337814bf6

  - BUILDINFO: QEMU upstream
    commit=44c5f0a55d9a73e592426c33ce5705c969681955

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - x86: correct create_bounce_frame (tagged with CVE
    number) (Boris Ostrovsky) [Orabug: 25927739]
    (CVE-2017-8905)

  - x86: discard type information when stealing pages
    (tagged with CVE number) (Boris Ostrovsky) [Orabug:
    25927669] (CVE-2017-8904)

  - multicall: deal with early exit conditions (tagged with
    CVE number) (Boris Ostrovsky) [Orabug: 25927592]
    (CVE-2017-8903)

  - BUILDINFO: xen
    commit=583dedab5ceddbae4d0384de0ade8feeee75f78c

  - BUILDINFO: QEMU upstream
    commit=fcd17fdf18b95a9e408acc84f6d2b37cf3fc0335

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - tools/libxc: Set max_elem to zero in
    xc_lockprof_query_number (Boris Ostrovsky) [Orabug:
    26020611]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2017-June/000744.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! preg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_exists(rpm:"xen-4.4.4-115", release:"OVS3.4") && rpm_check(release:"OVS3.4", reference:"xen-4.4.4-115.0.12.el6")) flag++;
if (rpm_exists(rpm:"xen-tools-4.4.4-115", release:"OVS3.4") && rpm_check(release:"OVS3.4", reference:"xen-tools-4.4.4-115.0.12.el6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-tools");
}
