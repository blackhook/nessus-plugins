#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104008);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-8399", "CVE-2017-1000111", "CVE-2017-1000112", "CVE-2017-11176", "CVE-2017-14106", "CVE-2017-7184", "CVE-2017-7541", "CVE-2017-7542", "CVE-2017-7558");

  script_name(english:"Scientific Linux Security Update : kernel on SL7.x x86_64 (20171019)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security Fix(es) :

  - Out-of-bounds kernel heap access vulnerability was found
    in xfrm, kernel's IP framework for transforming packets.
    An error dealing with netlink messages from an
    unprivileged user leads to arbitrary read/write and
    privilege escalation. (CVE-2017-7184, Important)

  - A race condition issue leading to a use-after-free flaw
    was found in the way the raw packet sockets are
    implemented in the Linux kernel networking subsystem
    handling synchronization. A local user able to open a
    raw packet socket (requires the CAP_NET_RAW capability)
    could use this flaw to elevate their privileges on the
    system. (CVE-2017-1000111, Important)

  - An exploitable memory corruption flaw was found in the
    Linux kernel. The append path can be erroneously
    switched from UFO to non-UFO in ip_ufo_append_data()
    when building an UFO packet with MSG_MORE option. If
    unprivileged user namespaces are available, this flaw
    can be exploited to gain root privileges.
    (CVE-2017-1000112, Important)

  - A flaw was found in the Linux networking subsystem where
    a local attacker with CAP_NET_ADMIN capabilities could
    cause an out-of-bounds memory access by creating a
    smaller-than-expected ICMP header and sending to its
    destination via sendto(). (CVE-2016-8399, Moderate)

  - Kernel memory corruption due to a buffer overflow was
    found in brcmf_cfg80211_mgmt_tx() function in Linux
    kernels from v3.9-rc1 to v4.13-rc1. The vulnerability
    can be triggered by sending a crafted NL80211_CMD_FRAME
    packet via netlink. This flaw is unlikely to be
    triggered remotely as certain userspace code is needed
    for this. An unprivileged local user could use this flaw
    to induce kernel memory corruption on the system,
    leading to a crash. Due to the nature of the flaw,
    privilege escalation cannot be fully ruled out, although
    it is unlikely. (CVE-2017-7541, Moderate)

  - An integer overflow vulnerability in
    ip6_find_1stfragopt() function was found. A local
    attacker that has privileges (of CAP_NET_RAW) to open
    raw socket can cause an infinite loop inside the
    ip6_find_1stfragopt() function. (CVE-2017-7542,
    Moderate)

  - A kernel data leak due to an out-of-bound read was found
    in the Linux kernel in inet_diag_msg_sctp{,l}addr_fill()
    and sctp_get_sctp_info() functions present since version
    4.7-rc1 through version 4.13. A data leak happens when
    these functions fill in sockaddr data structures used to
    export socket's diagnostic information. As a result, up
    to 100 bytes of the slab data could be leaked to a
    userspace. (CVE-2017-7558, Moderate)

  - The mq_notify function in the Linux kernel through
    4.11.9 does not set the sock pointer to NULL upon entry
    into the retry logic. During a user- space close of a
    Netlink socket, it allows attackers to possibly cause a
    situation where a value may be used after being freed
    (use-after-free) which may lead to memory corruption or
    other unspecified other impact. (CVE-2017-11176,
    Moderate)

  - A divide-by-zero vulnerability was found in the
    __tcp_select_window function in the Linux kernel. This
    can result in a kernel panic causing a local denial of
    service. (CVE-2017-14106, Moderate)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1710&L=scientific-linux-errata&F=&S=&P=12344
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?35dfde1c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-3.10.0-693.5.2.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kernel-abi-whitelists-3.10.0-693.5.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-3.10.0-693.5.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.10.0-693.5.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-693.5.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debuginfo-3.10.0-693.5.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.0-693.5.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-devel-3.10.0-693.5.2.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kernel-doc-3.10.0-693.5.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-headers-3.10.0-693.5.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-3.10.0-693.5.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-debuginfo-3.10.0-693.5.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-693.5.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-693.5.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perf-3.10.0-693.5.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perf-debuginfo-3.10.0-693.5.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-perf-3.10.0-693.5.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-perf-debuginfo-3.10.0-693.5.2.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-abi-whitelists / kernel-debug / etc");
}
