#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2020-0010.
#

include("compat.inc");

if (description)
{
  script_id(134611);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2019-14378", "CVE-2019-15890", "CVE-2020-7039");

  script_name(english:"OracleVM 3.4 : qemu-kvm (OVMSA-2020-0010)");
  script_summary(english:"Checks the RPM output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote OracleVM host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  -
    kvm-Fix-heap-overflow-in-ip_reass-on-big-packet-input.pa
    tch [bz#1734747]

  -
    kvm-Using-ip_deq-after-m_free-might-read-pointers-from-a
    .patch 

  - kvm-tcp_emu-Fix-oob-access.patch [bz#1791558]

  -
    kvm-slirp-use-correct-size-while-emulating-IRC-commands.
    patch [bz#1791558]

  -
    kvm-slirp-use-correct-size-while-emulating-commands.patc
    h [bz#1791558]

  - Resolves: bz#1734747 (CVE-2019-14378 qemu-kvm: QEMU:
    slirp: heap buffer overflow during packet reassembly
    [rhel-6.10.z])

  - Resolves: bz#1749731 (CVE-2019-15890 qemu-kvm: QEMU:
    Slirp: use-after-free during packet reassembly [rhel-6])

  - Resolves: bz#1791558 (CVE-2020-7039 qemu-kvm: QEMU:
    slirp: OOB buffer access while emulating tcp protocols
    in tcp_emu [rhel-6.10.z])"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2020-March/000973.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?74764caf"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected qemu-img package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7039");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:qemu-img");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"OVS3.4", reference:"qemu-img-0.12.1.2-2.506.el6_10.6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-img");
}
