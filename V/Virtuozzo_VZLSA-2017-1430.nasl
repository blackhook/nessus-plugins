#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101479);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id(
    "CVE-2017-7718",
    "CVE-2017-7980"
  );

  script_name(english:"Virtuozzo 7 : qemu-img / qemu-kvm / qemu-kvm-common / etc (VZLSA-2017-1430)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An update for qemu-kvm is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Kernel-based Virtual Machine (KVM) is a full virtualization solution
for Linux on a variety of architectures. The qemu-kvm package provides
the user-space component for running virtual machines that use KVM.

Security Fix(es) :

* An out-of-bounds r/w access issue was found in QEMU's Cirrus CLGD
54xx VGA Emulator support. The vulnerability could occur while copying
VGA data via various bitblt functions. A privileged user inside a
guest could use this flaw to crash the QEMU process or, potentially,
execute arbitrary code on the host with privileges of the QEMU
process. (CVE-2017-7980)

* An out-of-bounds access issue was found in QEMU's Cirrus CLGD 54xx
VGA Emulator support. The vulnerability could occur while copying VGA
data using bitblt functions (for example,
cirrus_bitblt_rop_fwd_transp_). A privileged user inside a guest could
use this flaw to crash the QEMU process, resulting in denial of
service. (CVE-2017-7718)

Red Hat would like to thank Jiangxin (PSIRT Huawei Inc) and Li Qiang
(Qihoo 360 Gear Team) for reporting CVE-2017-7980 and Jiangxin (PSIRT
Huawei Inc) for reporting CVE-2017-7718.

Bug Fix(es) :

* Previously, guest virtual machines in some cases became unresponsive
when the 'pty' back end of a serial device performed an irregular I/O
communication. This update improves the handling of serial I/O on
guests, which prevents the described problem from occurring.
(BZ#1452332)

Note that Tenable Network Security has attempted to extract the
preceding description block directly from the corresponding Red Hat
security advisory. Virtuozzo provides no description for VZLSA
advisories. Tenable has attempted to automatically clean and format
it as much as possible without introducing additional issues.");
  # http://repo.virtuozzo.com/vzlinux/announcements/json/VZLSA-2017-1430.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75ad6a40");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017-1430");
  script_set_attribute(attribute:"solution", value:
"Update the affected qemu-img / qemu-kvm / qemu-kvm-common / etc package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qemu-kvm-tools");
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

pkgs = ["qemu-img-1.5.3-126.vl7.9",
        "qemu-kvm-1.5.3-126.vl7.9",
        "qemu-kvm-common-1.5.3-126.vl7.9",
        "qemu-kvm-tools-1.5.3-126.vl7.9"];

foreach (pkg in pkgs)
  if (rpm_check(release:"Virtuozzo-7", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-img / qemu-kvm / qemu-kvm-common / etc");
}
