#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2018-0236.
#

include("compat.inc");

if (description)
{
  script_id(111021);
  script_version("1.5");
  script_cvs_date("Date: 2019/09/27 13:00:35");

  script_cve_id("CVE-2017-11600", "CVE-2017-18017", "CVE-2017-7616", "CVE-2017-8824", "CVE-2018-10087", "CVE-2018-10124", "CVE-2018-1130", "CVE-2018-5803");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2018-0236)");
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

  - block: update integrity interval after queue limits
    change (Ritika Srivastava) [Orabug: 27586756]

  - dccp: check sk for closed state in dccp_sendmsg (Alexey
    Kodanev) [Orabug: 28001529] (CVE-2017-8824)
    (CVE-2018-1130)

  - net/rds: Implement ARP flushing correctly (H&aring kon
    Bugge) [Orabug: 28219857]

  - net/rds: Fix incorrect bigger vs. smaller IP address
    check (H&aring kon Bugge) [Orabug: 28236599]

  - ocfs2: Fix locking for res->tracking and
    dlm->tracking_list (Ashish Samant) [Orabug: 28256391]

  - xfrm: policy: check policy direction value (Vladis
    Dronov) [Orabug: 28256487] (CVE-2017-11600)
    (CVE-2017-11600)

  - add kernel param to pre-allocate NICs (Brian Maly)
    [Orabug: 27870400]

  - mm/mempolicy.c: fix error handling in set_mempolicy and
    mbind. (Chris Salls) [Orabug: 28242475] (CVE-2017-7616)

  - xhci: Fix USB3 NULL pointer dereference at logical
    disconnect. (Mathias Nyman) [Orabug: 27426023]

  - mlx4_core: restore optimal ICM memory allocation (Eric
    Dumazet) 

  - mlx4_core: allocate ICM memory in page size chunks (Qing
    Huang) 

  - kernel/signal.c: avoid undefined behaviour in
    kill_something_info When running kill(72057458746458112,
    0) in userspace I hit the following issue. (mridula
    shastry) [Orabug: 28078687] (CVE-2018-10124)

  - rds: tcp: compute m_ack_seq as offset from ->write_seq
    (Sowmini Varadhan) [Orabug: 28085214]

  - ext4: fix bitmap position validation (Lukas Czerner)
    [Orabug: 28167032]

  - net/rds: Fix bug in failover_group parsing (H&aring kon
    Bugge) [Orabug: 28198749]

  - sctp: verify size of a new chunk in _sctp_make_chunk
    (Alexey Kodanev) [Orabug: 28240074] (CVE-2018-5803)

  - netfilter: xt_TCPMSS: add more sanity tests on
    tcph->doff (Eric Dumazet) [Orabug: 27896802]
    (CVE-2017-18017)

  - kernel/exit.c: avoid undefined behaviour when calling
    wait4 wait4(-2147483648, 0x20, 0, 0xdd0000) triggers:
    UBSAN: Undefined behaviour in kernel/exit.c:1651:9
    (mridula shastry) [Orabug: 28049778] (CVE-2018-10087)

  - x86/bugs/module: Provide retpoline_modules_only
    parameter to fail non-retpoline modules (Konrad
    Rzeszutek Wilk) [Orabug: 28071992]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2018-July/000872.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/12");
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
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-124.17.1.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-124.17.1.el6uek")) flag++;

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
