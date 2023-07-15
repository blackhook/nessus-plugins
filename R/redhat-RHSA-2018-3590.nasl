#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:3590. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(118947);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/09");

  script_cve_id("CVE-2017-18344", "CVE-2018-10675", "CVE-2018-14634", "CVE-2018-5391");
  script_xref(name:"RHSA", value:"2018:3590");

  script_name(english:"RHEL 7 : kernel (RHSA-2018:3590)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An update for kernel is now available for Red Hat Enterprise Linux 7.2
Advanced Update Support, Red Hat Enterprise Linux 7.2 Telco Extended
Update Support, and Red Hat Enterprise Linux 7.2 Update Services for
SAP Solutions.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* A flaw named FragmentSmack was found in the way the Linux kernel
handled reassembly of fragmented IPv4 and IPv6 packets. A remote
attacker could use this flaw to trigger time and calculation expensive
fragment reassembly algorithm by sending specially crafted packets
which could lead to a CPU saturation and hence a denial of service on
the system. (CVE-2018-5391)

* kernel: out-of-bounds access in the show_timer function in
kernel/time/ posix-timers.c (CVE-2017-18344)

* kernel: mm: use-after-free in do_get_mempolicy function allows local
DoS or other unspecified impact (CVE-2018-10675)

* kernel: Integer overflow in Linux's create_elf_tables function
(CVE-2018-14634)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank Juha-Matti Tilli (Aalto University -
Department of Communications and Networking and Nokia Bell Labs) for
reporting CVE-2018-5391 and Qualys Research Labs for reporting
CVE-2018-14634.

Bug Fix(es) :

* Previously, a kernel panic occurred when the kernel tried to make an
out of bound access to the array that describes the L1 Terminal Fault
(L1TF) mitigation state on systems without Extended Page Tables (EPT)
support. This update extends the array of mitigation states to cover
all the states, which effectively prevents out of bound array access.
Also, this update enables rejecting invalid, irrelevant values, that
might be erroneously provided by the userspace. As a result, the
kernel no longer panics in the described scenario. (BZ#1629565)

* Previously, a packet was missing the User Datagram Protocol (UDP)
payload checksum during a full checksum computation, if the hardware
checksum was not applied. As a consequence, a packet with an incorrect
checksum was dropped by a peer. With this update, the kernel includes
the UDP payload checksum during the full checksum computation. As a
result, the checksum is computed correctly and the packet can be
received by the peer. (BZ#1635792)

* Previously, a transform lookup through the xfrm framework could be
performed on an already transformed destination cache entry
(dst_entry). When using User Datagram Protocol (UDP) over IPv6 with a
connected socket in conjunction with Internet Protocol Security
(IPsec) in Encapsulating Security Payload (ESP) transport mode. As a
consequence, invalid IPv6 fragments transmitted from the host or the
kernel occasionally terminated unexpectedly due to a socket buffer
(SKB) underrun. With this update, the xfrm lookup on an already
transformed dst_entry is not possible. As a result, using UDP iperf
utility over IPv6 ESP no longer causes invalid IPv6 fragment
transmissions or a kernel panic. (BZ#1639586)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/articles/3553061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/vulnerabilities/mutagen-astronomy"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:3590"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-18344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-5391"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-10675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-14634"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14634");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");
include("ksplice.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^7\.2([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.2", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2017-18344", "CVE-2018-10675", "CVE-2018-14634", "CVE-2018-5391");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2018:3590");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2018:3590";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-3.10.0-327.76.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", reference:"kernel-abi-whitelists-3.10.0-327.76.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-debug-3.10.0-327.76.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.10.0-327.76.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-327.76.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-debuginfo-3.10.0-327.76.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.0-327.76.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-devel-3.10.0-327.76.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", reference:"kernel-doc-3.10.0-327.76.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-headers-3.10.0-327.76.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-tools-3.10.0-327.76.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-tools-debuginfo-3.10.0-327.76.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-327.76.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-327.76.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"perf-3.10.0-327.76.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"perf-debuginfo-3.10.0-327.76.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"python-perf-3.10.0-327.76.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"python-perf-debuginfo-3.10.0-327.76.1.el7")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-abi-whitelists / kernel-debug / etc");
  }
}
