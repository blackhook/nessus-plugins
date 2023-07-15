#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0108. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127343);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2016-2857",
    "CVE-2016-3712",
    "CVE-2016-9603",
    "CVE-2017-2615",
    "CVE-2017-2620",
    "CVE-2017-2633",
    "CVE-2017-7718",
    "CVE-2017-7980"
  );
  script_bugtraq_id(102129);

  script_name(english:"NewStart CGSL MAIN 4.05 : qemu-kvm Multiple Vulnerabilities (NS-SA-2019-0108)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.05, has qemu-kvm packages installed that are affected by multiple
vulnerabilities:

  - Quick emulator (QEMU) built with the Cirrus CLGD 54xx
    VGA Emulator support is vulnerable to an out-of-bounds
    access issue. The issue could occur while copying VGA
    data in cirrus_bitblt_cputovideo. A privileged user
    inside guest could use this flaw to crash the QEMU
    process OR potentially execute arbitrary code on host
    with privileges of the QEMU process. (CVE-2017-2620)

  - Quick emulator (QEMU) built with the Cirrus CLGD 54xx
    VGA emulator support is vulnerable to an out-of-bounds
    access issue. It could occur while copying VGA data via
    bitblt copy in backward mode. A privileged user inside a
    guest could use this flaw to crash the QEMU process
    resulting in DoS or potentially execute arbitrary code
    on the host with privileges of QEMU process on the host.
    (CVE-2017-2615)

  - An out-of-bounds memory access issue was found in Quick
    Emulator (QEMU) in the VNC display driver. This flaw
    could occur while refreshing the VNC display surface
    area in the 'vnc_refresh_server_surface'. A user inside
    a guest could use this flaw to crash the QEMU process.
    (CVE-2017-2633)

  - An integer overflow flaw and an out-of-bounds read flaw
    were found in the way QEMU's VGA emulator set certain
    VGA registers while in VBE mode. A privileged guest user
    could use this flaw to crash the QEMU process instance.
    (CVE-2016-3712)

  - An out-of-bounds read-access flaw was found in the QEMU
    emulator built with IP checksum routines. The flaw could
    occur when computing a TCP/UDP packet's checksum,
    because a QEMU function used the packet's payload length
    without checking against the data buffer's size. A user
    inside a guest could use this flaw to crash the QEMU
    process (denial of service). (CVE-2016-2857)

  - A heap buffer overflow flaw was found in QEMU's Cirrus
    CLGD 54xx VGA emulator's VNC display driver support; the
    issue could occur when a VNC client attempted to update
    its display after a VGA operation is performed by a
    guest. A privileged user/process inside a guest could
    use this flaw to crash the QEMU process or, potentially,
    execute arbitrary code on the host with privileges of
    the QEMU process. (CVE-2016-9603)

  - An out-of-bounds access issue was found in QEMU's Cirrus
    CLGD 54xx VGA Emulator support. The vulnerability could
    occur while copying VGA data using bitblt functions (for
    example, cirrus_bitblt_rop_fwd_transp_). A privileged
    user inside a guest could use this flaw to crash the
    QEMU process, resulting in denial of service.
    (CVE-2017-7718)

  - An out-of-bounds r/w access issue was found in QEMU's
    Cirrus CLGD 54xx VGA Emulator support. The vulnerability
    could occur while copying VGA data via various bitblt
    functions. A privileged user inside a guest could use
    this flaw to crash the QEMU process or, potentially,
    execute arbitrary code on the host with privileges of
    the QEMU process. (CVE-2017-7980)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0108");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL qemu-kvm packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-2620");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/12");
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

if (release !~ "CGSL MAIN 4.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 4.05": [
    "qemu-guest-agent-0.12.1.2-2.503.el6_9.3.3",
    "qemu-img-0.12.1.2-2.503.el6_9.3.3",
    "qemu-kvm-0.12.1.2-2.503.el6_9.3.3",
    "qemu-kvm-tools-0.12.1.2-2.503.el6_9.3.3"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-kvm");
}
