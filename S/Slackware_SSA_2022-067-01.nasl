#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2022-067-01. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158743);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/16");

  script_cve_id(
    "CVE-2022-0435",
    "CVE-2022-0487",
    "CVE-2022-0492",
    "CVE-2022-0516",
    "CVE-2022-0847",
    "CVE-2022-25258",
    "CVE-2022-25375",
    "CVE-2022-25636"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/16");

  script_name(english:"Slackware Linux 15.0 kernel-generic  Multiple Vulnerabilities (SSA:2022-067-01)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to kernel-generic.");
  script_set_attribute(attribute:"description", value:
"The version of kernel-generic installed on the remote host is prior to 5.15.27 / 5.15.27_smp. It is, therefore, affected
by multiple vulnerabilities as referenced in the SSA:2022-067-01 advisory.

  - A use-after-free vulnerability was found in rtsx_usb_ms_drv_remove in drivers/memstick/host/rtsx_usb_ms.c
    in memstick in the Linux kernel. In this flaw, a local attacker with a user privilege may impact system
    Confidentiality. This flaw affects kernel versions prior to 5.14 rc1. (CVE-2022-0487)

  - A vulnerability was found in the Linux kernel's cgroup_release_agent_write in the
    kernel/cgroup/cgroup-v1.c function. This flaw, under certain circumstances, allows the use of the cgroups
    v1 release_agent feature to escalate privileges and bypass the namespace isolation unexpectedly.
    (CVE-2022-0492)

  - An issue was discovered in drivers/usb/gadget/composite.c in the Linux kernel before 5.16.10. The USB
    Gadget subsystem lacks certain validation of interface OS descriptor requests (ones with a large array
    index and ones associated with NULL function pointer retrieval). Memory corruption might occur.
    (CVE-2022-25258)

  - An issue was discovered in drivers/usb/gadget/function/rndis.c in the Linux kernel before 5.16.10. The
    RNDIS USB gadget lacks validation of the size of the RNDIS_MSG_SET command. Attackers can obtain sensitive
    information from kernel memory. (CVE-2022-25375)

  - net/netfilter/nf_dup_netdev.c in the Linux kernel 5.4 through 5.6.10 allows local users to gain privileges
    because of a heap out-of-bounds write. This is related to nf_tables_offload. (CVE-2022-25636)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected kernel-generic package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0435");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Dirty Pipe Local Privilege Escalation via CVE-2022-0847');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-generic-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-huge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-huge-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-modules-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:15.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Slackware Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Slackware/release", "Host/Slackware/packages");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("slackware.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Slackware/release")) audit(AUDIT_OS_NOT, "Slackware");
if (!get_kb_item("Host/Slackware/packages")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Slackware", cpu);

var flag = 0;
var constraints = [
    { 'fixed_version' : '5.15.27', 'product' : 'kernel-generic', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '5.15.27', 'product' : 'kernel-huge', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '5.15.27', 'product' : 'kernel-modules', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '5.15.27_smp', 'product' : 'kernel-generic-smp', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'i686' },
    { 'fixed_version' : '5.15.27_smp', 'product' : 'kernel-huge-smp', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'i686' },
    { 'fixed_version' : '5.15.27_smp', 'product' : 'kernel-modules-smp', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'i686' },
    { 'fixed_version' : '5.15.27', 'product' : 'kernel-source', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'noarch' },
    { 'fixed_version' : '5.15.27_smp', 'product' : 'kernel-source', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'noarch' },
    { 'fixed_version' : '5.15.27', 'product' : 'kernel-headers', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'x86' },
    { 'fixed_version' : '5.15.27_smp', 'product' : 'kernel-headers', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'x86' },
    { 'fixed_version' : '5.15.27', 'product' : 'kernel-generic', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'x86_64' },
    { 'fixed_version' : '5.15.27', 'product' : 'kernel-huge', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'x86_64' },
    { 'fixed_version' : '5.15.27', 'product' : 'kernel-modules', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'x86_64' }
];

foreach constraint (constraints) {
    var pkg_arch = constraint['arch'];
    var arch = NULL;
    if (pkg_arch == "x86_64") {
        arch = pkg_arch;
    }
    if (slackware_check(osver:constraint['os_version'],
                        arch:arch,
                        pkgname:constraint['product'],
                        pkgver:constraint['fixed_version'],
                        pkgarch:pkg_arch,
                        pkgnum:constraint['service_pack'])) flag++;
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : slackware_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
