#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0211. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131771);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2018-10839",
    "CVE-2018-11806",
    "CVE-2018-17962",
    "CVE-2019-6778",
    "CVE-2019-12155"
  );
  script_bugtraq_id(106758, 108429);

  script_name(english:"NewStart CGSL MAIN 4.06 : qemu-kvm Multiple Vulnerabilities (NS-SA-2019-0211)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.06, has qemu-kvm packages installed that are affected by multiple
vulnerabilities:

  - m_cat in slirp/mbuf.c in Qemu has a heap-based buffer
    overflow via incoming fragmented datagrams.
    (CVE-2018-11806)

  - Qemu emulator <= 3.0.0 built with the NE2000 NIC
    emulation support is vulnerable to an integer overflow,
    which could lead to buffer overflow issue. It could
    occur when receiving packets over the network. A user
    inside guest could use this flaw to crash the Qemu
    process resulting in DoS. (CVE-2018-10839)

  - Qemu has a Buffer Overflow in pcnet_receive in
    hw/net/pcnet.c because an incorrect integer data type is
    used. (CVE-2018-17962)

  - In QEMU 3.0.0, tcp_emu in slirp/tcp_subr.c has a heap-
    based buffer overflow. (CVE-2019-6778)

  - interface_release_resource in hw/display/qxl.c in QEMU
    4.0.0 has a NULL pointer dereference. (CVE-2019-12155)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0211");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL qemu-kvm packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11806");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/06");

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

if (release !~ "CGSL MAIN 4.06")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.06');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 4.06": [
    "qemu-guest-agent-0.12.1.2-2.506.el6_10.5",
    "qemu-img-0.12.1.2-2.506.el6_10.5",
    "qemu-kvm-0.12.1.2-2.506.el6_10.5",
    "qemu-kvm-debuginfo-0.12.1.2-2.506.el6_10.5",
    "qemu-kvm-tools-0.12.1.2-2.506.el6_10.5"
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
