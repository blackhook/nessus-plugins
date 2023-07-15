#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0167.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104453);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-1000112", "CVE-2017-10661", "CVE-2017-12154", "CVE-2017-14106", "CVE-2017-14489", "CVE-2017-7482", "CVE-2017-7541", "CVE-2017-7542", "CVE-2017-7618");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2017-0167)");
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

  - Revert 'drivers/char/mem.c: deny access in open
    operation when securelevel is set' (Brian Maly) [Orabug:
    27037811]

  - xfs: use dedicated log worker wq to avoid deadlock with
    cil wq (Brian Foster) [Orabug: 27013241]

  - scsi: scsi_transport_iscsi: fix the issue that
    iscsi_if_rx doesn't parse nlmsg properly (Xin Long)
    [Orabug: 26988633] (CVE-2017-14489)

  - nvme: honor RTD3 Entry Latency for shutdowns (Martin K.
    Petersen) 

  - ipv6: avoid overflow of offset in ip6_find_1stfragopt
    (Sabrina Dubroca) [Orabug: 27013220] (CVE-2017-7542)

  - udp: consistently apply ufo or fragmentation (Willem de
    Bruijn) [Orabug: 27013227] (CVE-2017-1000112)

  - drivers/char/mem.c: deny access in open operation when
    securelevel is set (Ethan Zhao) [Orabug: 26943884]

  - tcp: fix tcp_mark_head_lost to check skb len before
    fragmenting (Neal Cardwell) [Orabug: 26923675]

  - timerfd: Protect the might cancel mechanism proper
    (Thomas Gleixner) [Orabug: 26899775] (CVE-2017-10661)

  - kvm: nVMX: Don't allow L2 to access the hardware CR8
    (Jim Mattson) (CVE-2017-12154) (CVE-2017-12154)

  - brcmfmac: fix possible buffer overflow in
    brcmf_cfg80211_mgmt_tx (Tim Tianyang Chen) [Orabug:
    26880590] (CVE-2017-7541)

  - crypto: ahash - Fix EINPROGRESS notification callback
    (Herbert Xu) [Orabug: 26916575] (CVE-2017-7618)

  - ovl: use O_LARGEFILE in ovl_copy_up (David Howells)
    [Orabug: 25953280]

  - rxrpc: Fix several cases where a padded len isn't
    checked in ticket decode (David Howells) [Orabug:
    26880508] (CVE-2017-7482) (CVE-2017-7482)

  - tcp: initialize rcv_mss to TCP_MIN_MSS instead of 0 (Wei
    Wang) [Orabug: 26813385] (CVE-2017-14106)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-November/000798.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f3068531"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel UDP Fragmentation Offset (UFO) Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/08");
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
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-103.9.2.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-103.9.2.el6uek")) flag++;

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
