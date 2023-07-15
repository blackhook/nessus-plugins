#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2018-0028.
#

include("compat.inc");

if (description)
{
  script_id(108823);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/15");

  script_cve_id("CVE-2017-5715");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"OracleVM 3.4 : xen (OVMSA-2018-0028) (Spectre)");
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

  - BUILDINFO: OVMF
    commit=173bf5c847e3ca8b42c11796ce048d8e2e916ff8

  - BUILDINFO: xen
    commit=bf523bc61677448cb7bb79980d6969896d005bd5

  - BUILDINFO: QEMU upstream
    commit=8bff6989bd0bafcc0ddf859c23ce6a2ff21a80ff

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - hvmloader: Initialize a variable before we use it
    (Patrick Colp) 

  - x86/hvm: indicate avaliability of HW support of APIC
    virtualization to HVM guests (Boris Ostrovsky) [Orabug:
    27739755]

  - x86/boot: Disable IBRS in intr/nmi exit path at bootup
    stage (Zhenzhong Duan) [Orabug: 27411047]

  - Fix a wrong check in DO_SPEC_CTRL_EXIT_TO_XEN (Zhenzhong
    Duan) [Orabug: 27738692] (CVE-2017-5715)

  - BUILDINFO: OVMF
    commit=173bf5c847e3ca8b42c11796ce048d8e2e916ff8

  - BUILDINFO: xen
    commit=eb6d0ea26496051c6ab876e4037fca0b9cf079d9

  - BUILDINFO: QEMU upstream
    commit=8bff6989bd0bafcc0ddf859c23ce6a2ff21a80ff

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - xenstore: add assertion in database dumping code (Wei
    Liu) [Orabug: 27608242]

  - xenstore: send error earlier in do_mkdir (Wei Liu)
    [Orabug: 27608242]

  - xenstore: add memory allocation debugging capability
    (Juergen Gross) 

  - xenstore: use temporary memory context for firing
    watches (Juergen Gross) [Orabug: 27608242]

  - xenstore: add explicit memory context parameter to
    get_node (Juergen Gross) [Orabug: 27608242]

  - xenstore: add explicit memory context parameter to
    read_node (Juergen Gross) [Orabug: 27608242]

  - xenstore: add explicit memory context parameter to
    get_parent (Juergen Gross) [Orabug: 27608242]

  - xenstore: call each xenstored command function with
    temporary context (Juergen Gross) [Orabug: 27608242]

  - cxenstored: document a bunch of short options in help
    string (Wei Liu) [Orabug: 27608242]

  - BUILDINFO: OVMF
    commit=173bf5c847e3ca8b42c11796ce048d8e2e916ff8

  - BUILDINFO: xen
    commit=18c714d6839a3fd0d42a5400de940c5b5e788a8c

  - BUILDINFO: QEMU upstream
    commit=8bff6989bd0bafcc0ddf859c23ce6a2ff21a80ff

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - x86/spectre: Make retpoline code match upstream version
    (Patrick Colp) 

  - xenbaked.c: Avoid divide by zero issue (Joe Jin)
    [Orabug: 27687906]

  - xen/trace: Fix trace metadata page count calculation
    (revert fbf96e6) (George Dunlap) [Orabug: 27602524]

  - x86/traps/spectre: Fix IO emulation stub code (Boris
    Ostrovsky) [Orabug: 27693394] (CVE-2017-5715)

  - BUILDINFO: OVMF
    commit=173bf5c847e3ca8b42c11796ce048d8e2e916ff8

  - BUILDINFO: xen
    commit=fa171d3584f49dae46fcea63516b25465473a83b

  - BUILDINFO: QEMU upstream
    commit=8bff6989bd0bafcc0ddf859c23ce6a2ff21a80ff

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - xend: use vcpus variable in log.warn (Elena Ufimtseva) -
    xend: turn off smt if vcpus are not multiple of threads
    (Elena Ufimtseva) [Orabug: 27648711]

  - xend: fix preserving smt across reboot (Elena Ufimtseva)
    [Orabug: 27648711]

  - xend: fix is_vnuma_off function (Elena Ufimtseva)

  - BUILDINFO: OVMF
    commit=173bf5c847e3ca8b42c11796ce048d8e2e916ff8

  - BUILDINFO: xen
    commit=131bef465d7329311ec1d9d8f8011a1ceb8d32fe

  - BUILDINFO: QEMU upstream
    commit=8bff6989bd0bafcc0ddf859c23ce6a2ff21a80ff

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - mm, sysctl, xend: only create when there's enough
    scrubbed memory (Joao Martins) [Orabug: 27450131]"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2018-April/000838.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0c2bd755"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected xen / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/04");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_exists(rpm:"xen-4.4.4-155", release:"OVS3.4") && rpm_check(release:"OVS3.4", reference:"xen-4.4.4-155.0.27.el6")) flag++;
if (rpm_exists(rpm:"xen-tools-4.4.4-155", release:"OVS3.4") && rpm_check(release:"OVS3.4", reference:"xen-tools-4.4.4-155.0.27.el6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-tools");
}
