#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2018-0256.
#

include("compat.inc");

if (description)
{
  script_id(117512);
  script_version("1.3");
  script_cvs_date("Date: 2019/09/27 13:00:35");

  script_cve_id("CVE-2018-5390");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2018-0256)");
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

  - tcp: add tcp_ooo_try_coalesce helper (Eric Dumazet)
    [Orabug: 28639707] (CVE-2018-5390)

  - tcp: call tcp_drop from tcp_data_queue_ofo (Eric
    Dumazet) [Orabug: 28639707] (CVE-2018-5390)

  - tcp: detect malicious patterns in tcp_collapse_ofo_queue
    (Eric Dumazet) [Orabug: 28639707] (CVE-2018-5390)

  - tcp: avoid collapses in tcp_prune_queue if possible
    (Eric Dumazet) [Orabug: 28639707] (CVE-2018-5390)

  - tcp: free batches of packets in tcp_prune_ofo_queue
    (Eric Dumazet) [Orabug: 28639707] (CVE-2018-5390)

  - tcp: use an RB tree for ooo receive queue (Yaogong Wang)
    [Orabug: 28639707] (CVE-2018-5390)

  - tcp: refine tcp_prune_ofo_queue to not drop all packets
    (Eric Dumazet) [Orabug: 28639707] (CVE-2018-5390)

  - tcp: introduce tcp_under_memory_pressure (Eric Dumazet)
    [Orabug: 28639707] (CVE-2018-5390)

  - tcp: increment sk_drops for dropped rx packets (Eric
    Dumazet) [Orabug: 28639707] (CVE-2018-5390)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2018-September/000891.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ba4c0b8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-124.19.2.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-124.19.2.el6uek")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}
