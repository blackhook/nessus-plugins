#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101431);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id(
    "CVE-2016-8630",
    "CVE-2016-8655",
    "CVE-2016-9083",
    "CVE-2016-9084"
  );

  script_name(english:"Virtuozzo 7 : kernel / kernel-abi-whitelists / kernel-debug / etc (VZLSA-2017-0386)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An update for kernel is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* Linux kernel built with the Kernel-based Virtual Machine
(CONFIG_KVM) support is vulnerable to a NULL pointer dereference flaw.
It could occur on x86 platform, when emulating an undefined
instruction. An attacker could use this flaw to crash the host kernel
resulting in DoS. (CVE-2016-8630, Important)

* A race condition issue leading to a use-after-free flaw was found in
the way the raw packet sockets implementation in the Linux kernel
networking subsystem handled synchronization while creating the
TPACKET_V3 ring buffer. A local user able to open a raw packet socket
(requires the CAP_NET_RAW capability) could use this flaw to elevate
their privileges on the system. (CVE-2016-8655, Important)

* A flaw was discovered in the Linux kernel's implementation of VFIO.
An attacker issuing an ioctl can create a situation where memory is
corrupted and modify memory outside of the expected area. This may
overwrite kernel memory and subvert kernel execution. (CVE-2016-9083,
Important)

* The use of a kzalloc with an integer multiplication allowed an
integer overflow condition to be reached in vfio_pci_intrs.c. This
combined with CVE-2016-9083 may allow an attacker to craft an attack
and use unallocated memory, potentially crashing the machine.
(CVE-2016-9084, Moderate)

Red Hat would like to thank Philip Pettersson for reporting
CVE-2016-8655.

Additional Changes :

Space precludes documenting all of the bug fixes and enhancements
included in this advisory. To see the complete list of bug fixes and
enhancements, refer to the following KnowledgeBase article:
https://access.redhat.com/articles/ 2940041.

Note that Tenable Network Security has attempted to extract the
preceding description block directly from the corresponding Red Hat
security advisory. Virtuozzo provides no description for VZLSA
advisories. Tenable has attempted to automatically clean and format
it as much as possible without introducing additional issues.");
  # http://repo.virtuozzo.com/vzlinux/announcements/json/VZLSA-2017-0386.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43a5fb2d");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017-0386");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel / kernel-abi-whitelists / kernel-debug / etc package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'AF_PACKET chocobo_root Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:7");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Virtuozzo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Virtuozzo/release", "Host/Virtuozzo/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/Virtuozzo/release");
if (isnull(release) || "Virtuozzo" >!< release) audit(AUDIT_OS_NOT, "Virtuozzo");
os_ver = pregmatch(pattern: "Virtuozzo Linux release ([0-9]+\.[0-9])(\D|$)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Virtuozzo");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Virtuozzo 7.x", "Virtuozzo " + os_ver);

if (!get_kb_item("Host/Virtuozzo/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Virtuozzo", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-514.10.2.vl7",
        "kernel-abi-whitelists-3.10.0-514.10.2.vl7",
        "kernel-debug-3.10.0-514.10.2.vl7",
        "kernel-debug-devel-3.10.0-514.10.2.vl7",
        "kernel-devel-3.10.0-514.10.2.vl7",
        "kernel-doc-3.10.0-514.10.2.vl7",
        "kernel-headers-3.10.0-514.10.2.vl7",
        "kernel-tools-3.10.0-514.10.2.vl7",
        "kernel-tools-libs-3.10.0-514.10.2.vl7",
        "kernel-tools-libs-devel-3.10.0-514.10.2.vl7",
        "perf-3.10.0-514.10.2.vl7",
        "python-perf-3.10.0-514.10.2.vl7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"Virtuozzo-7", reference:pkg)) flag++;

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
