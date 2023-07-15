#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101474);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id(
    "CVE-2016-10208",
    "CVE-2016-7910",
    "CVE-2016-8646",
    "CVE-2017-5986",
    "CVE-2017-7308"
  );

  script_name(english:"Virtuozzo 7 : kernel / kernel-abi-whitelists / kernel-debug / etc (VZLSA-2017-1308)");
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

* It was found that the packet_set_ring() function of the Linux
kernel's networking implementation did not properly validate certain
block-size data. A local attacker with CAP_NET_RAW capability could
use this flaw to trigger a buffer overflow, resulting in the crash of
the system. Due to the nature of the flaw, privilege escalation cannot
be fully ruled out. (CVE-2017-7308, Important)

* Mounting a crafted EXT4 image read-only leads to an attacker
controlled memory corruption and SLAB-Out-of-Bounds reads.
(CVE-2016-10208, Moderate)

* A flaw was found in the Linux kernel's implementation of seq_file
where a local attacker could manipulate memory in the put() function
pointer. This could lead to memory corruption and possible privileged
escalation. (CVE-2016-7910, Moderate)

* A vulnerability was found in the Linux kernel. An unprivileged local
user could trigger oops in shash_async_export() by attempting to force
the in-kernel hashing algorithms into decrypting an empty data set.
(CVE-2016-8646, Moderate)

* It was reported that with Linux kernel, earlier than version
v4.10-rc8, an application may trigger a BUG_ON in sctp_wait_for_sndbuf
if the socket tx buffer is full, a thread is waiting on it to queue
more data, and meanwhile another thread peels off the association
being used by the first thread. (CVE-2017-5986, Moderate)

Red Hat would like to thank Igor Redko (Virtuozzo kernel team) for
reporting CVE-2016-8646.

Additional Changes :

This update also fixes several bugs and adds various enhancements.
Documentation for these changes is available from the Technical Notes
document linked to in the References section.

Note that Tenable Network Security has attempted to extract the
preceding description block directly from the corresponding Red Hat
security advisory. Virtuozzo provides no description for VZLSA
advisories. Tenable has attempted to automatically clean and format
it as much as possible without introducing additional issues.");
  # http://repo.virtuozzo.com/vzlinux/announcements/json/VZLSA-2017-1308.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ab2f0c4");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017-1308");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel / kernel-abi-whitelists / kernel-debug / etc package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'AF_PACKET packet_set_ring Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/26");

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

pkgs = ["kernel-3.10.0-514.21.1.vl7",
        "kernel-abi-whitelists-3.10.0-514.21.1.vl7",
        "kernel-debug-3.10.0-514.21.1.vl7",
        "kernel-debug-devel-3.10.0-514.21.1.vl7",
        "kernel-devel-3.10.0-514.21.1.vl7",
        "kernel-doc-3.10.0-514.21.1.vl7",
        "kernel-headers-3.10.0-514.21.1.vl7",
        "kernel-tools-3.10.0-514.21.1.vl7",
        "kernel-tools-libs-3.10.0-514.21.1.vl7",
        "kernel-tools-libs-devel-3.10.0-514.21.1.vl7",
        "perf-3.10.0-514.21.1.vl7",
        "python-perf-3.10.0-514.21.1.vl7"];

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
