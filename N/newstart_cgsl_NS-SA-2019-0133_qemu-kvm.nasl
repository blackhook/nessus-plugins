#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0133. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(127389);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/15");

  script_cve_id(
    "CVE-2017-13672",
    "CVE-2018-3639",
    "CVE-2018-5683",
    "CVE-2018-7858"
  );

  script_name(english:"NewStart CGSL MAIN 4.05 : qemu-kvm Multiple Vulnerabilities (NS-SA-2019-0133)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.05, has qemu-kvm packages installed that are affected by multiple
vulnerabilities:

  - An out-of-bounds read access issue was found in the VGA
    display emulator built into the Quick emulator (QEMU).
    It could occur while reading VGA memory to update
    graphics display. A privileged user/process inside guest
    could use this flaw to crash the QEMU process on the
    host resulting in denial of service situation.
    (CVE-2017-13672)

  - An industry-wide issue was found in the way many modern
    microprocessor designs have implemented speculative
    execution of Load & Store instructions (a commonly used
    performance optimization). It relies on the presence of
    a precisely-defined instruction sequence in the
    privileged code as well as the fact that memory read
    from address to which a recent memory write has occurred
    may see an older value and subsequently cause an update
    into the microprocessor's data cache even for
    speculatively executed instructions that never actually
    commit (retire). As a result, an unprivileged attacker
    could use this flaw to read privileged memory by
    conducting targeted cache side-channel attacks.
    (CVE-2018-3639)

  - Quick Emulator (aka QEMU), when built with the Cirrus
    CLGD 54xx VGA Emulator support, allows local guest OS
    privileged users to cause a denial of service (out-of-
    bounds access and QEMU process crash) by leveraging
    incorrect region calculation when updating VGA display.
    (CVE-2018-7858)

  - An out-of-bounds read access issue was found in the VGA
    emulator of QEMU. It could occur in vga_draw_text
    routine, while updating display area for a vnc client. A
    privileged user inside a guest could use this flaw to
    crash the QEMU process resulting in DoS. (CVE-2018-5683)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0133");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL qemu-kvm packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3639");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/01");
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
    "qemu-guest-agent-0.12.1.2-2.506.el6_10.1",
    "qemu-img-0.12.1.2-2.506.el6_10.1",
    "qemu-kvm-0.12.1.2-2.506.el6_10.1",
    "qemu-kvm-debuginfo-0.12.1.2-2.506.el6_10.1",
    "qemu-kvm-tools-0.12.1.2-2.506.el6_10.1"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
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
