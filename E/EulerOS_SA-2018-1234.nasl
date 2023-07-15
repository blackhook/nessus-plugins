#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117543);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-13215",
    "CVE-2017-15129",
    "CVE-2017-18017",
    "CVE-2017-18079",
    "CVE-2018-5332",
    "CVE-2018-5333"
  );

  script_name(english:"EulerOS Virtualization 2.5.0 : kernel (EulerOS-SA-2018-1234)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - A use-after-free vulnerability was found in network
    namespaces code affecting the Linux kernel before
    4.14.11. The function get_net_ns_by_id() in
    net/core/net_namespace.c does not check for the
    net::count value after it has found a peer network in
    netns_ids idr, which could lead to double free and
    memory corruption. This vulnerability could allow an
    unprivileged local user to induce kernel memory
    corruption on the system, leading to a crash. Due to
    the nature of the flaw, privilege escalation cannot be
    fully ruled out, although it is thought to be
    unlikely.(CVE-2017-15129)

  - The tcpmss_mangle_packet function in
    net/netfilter/xt_TCPMSS.c in the Linux kernel before
    4.11, and 4.9.x before 4.9.36, allows remote attackers
    to cause a denial of service (use-after-free and memory
    corruption) or possibly have unspecified other impact
    by leveraging the presence of xt_TCPMSS in an iptables
    action.(CVE-2017-18017)

  - A flaw was found in the upstream kernel Skcipher
    component. This vulnerability affects the
    skcipher_recvmsg function of the component Skcipher.
    The manipulation with an unknown input leads to a
    privilege escalation vulnerability.(CVE-2017-13215)

  - In the Linux kernel through 4.14.13, the
    rds_message_alloc_sgs() function does not validate a
    value that is used during DMA page allocation, leading
    to a heap-based out-of-bounds write (related to the
    rds_rdma_extra_size() function in 'net/rds/rdma.c') and
    thus to a system panic. Due to the nature of the flaw,
    privilege escalation cannot be fully ruled out,
    although we believe it is unlikely.(CVE-2018-5332)

  - In the Linux kernel through 4.14.13, the
    rds_cmsg_atomic() function in 'net/rds/rdma.c'
    mishandles cases where page pinning fails or an invalid
    address is supplied by a user. This can lead to a NULL
    pointer dereference in rds_atomic_free_op() and thus to
    a system panic.(CVE-2018-5333)

  - drivers/input/serio/i8042.c in the Linux kernel before
    4.12.4 allows attackers to cause a denial of service
    (NULL pointer dereference and system crash) or possibly
    have unspecified other impact because the
    port-i1/4zexists value can change after it is
    validated.(CVE-2017-18079)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1234
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10ab5c96");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Reliable Datagram Sockets (RDS) rds_atomic_free_op NULL pointer dereference Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.5.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "2.5.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.5.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-327.61.59.66_25",
        "kernel-devel-3.10.0-327.61.59.66_25",
        "kernel-headers-3.10.0-327.61.59.66_25",
        "kernel-tools-3.10.0-327.61.59.66_25",
        "kernel-tools-libs-3.10.0-327.61.59.66_25",
        "kernel-tools-libs-devel-3.10.0-327.61.59.66_25"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
