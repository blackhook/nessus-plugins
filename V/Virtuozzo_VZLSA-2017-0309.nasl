#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101428);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id(
    "CVE-2016-2857",
    "CVE-2017-2615"
  );
  script_xref(name:"IAVB", value:"2017-B-0024-S");

  script_name(english:"Virtuozzo 6 : qemu-guest-agent / qemu-img / qemu-kvm / etc (VZLSA-2017-0309)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An update for qemu-kvm is now available for Red Hat Enterprise Linux
6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Kernel-based Virtual Machine (KVM) is a full virtualization solution
for Linux on a variety of architectures. The qemu-kvm packages provide
the user-space component for running virtual machines that use KVM.

Security Fix(es) :

* Quick emulator (Qemu) built with the Cirrus CLGD 54xx VGA emulator
support is vulnerable to an out-of-bounds access issue. It could occur
while copying VGA data via bitblt copy in backward mode. A privileged
user inside a guest could use this flaw to crash the Qemu process
resulting in DoS or potentially execute arbitrary code on the host
with privileges of Qemu process on the host. (CVE-2017-2615)

* An out-of-bounds read-access flaw was found in the QEMU emulator
built with IP checksum routines. The flaw could occur when computing a
TCP/UDP packet's checksum, because a QEMU function used the packet's
payload length without checking against the data buffer's size. A user
inside a guest could use this flaw to crash the QEMU process (denial
of service). (CVE-2016-2857)

Red Hat would like to thank Wjjzhang (Tencent.com Inc.) Li Qiang
(360.cn Inc.) for reporting CVE-2017-2615 and Ling Liu (Qihoo 360
Inc.) for reporting CVE-2016-2857.

This update also fixes the following bug :

* Previously, rebooting a guest virtual machine more than 128 times in
a short period of time caused the guest to shut down instead of
rebooting, because the virtqueue was not cleaned properly. This update
ensures that the virtqueue is cleaned more reliably, which prevents
the described problem from occurring. (BZ#1408389)

All qemu-kvm users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing this update, shut down all running virtual machines. Once
all virtual machines have shut down, start them again for this update
to take effect.

Note that Tenable Network Security has attempted to extract the
preceding description block directly from the corresponding Red Hat
security advisory. Virtuozzo provides no description for VZLSA
advisories. Tenable has attempted to automatically clean and format
it as much as possible without introducing additional issues.");
  # http://repo.virtuozzo.com/vzlinux/announcements/json/VZLSA-2017-0309.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?297c9065");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017-0309");
  script_set_attribute(attribute:"solution", value:
"Update the affected qemu-guest-agent / qemu-img / qemu-kvm / etc package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:6");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/13");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Virtuozzo 6.x", "Virtuozzo " + os_ver);

if (!get_kb_item("Host/Virtuozzo/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Virtuozzo", cpu);

flag = 0;

pkgs = ["qemu-guest-agent-0.12.1.2-2.491.vl6.6",
        "qemu-img-0.12.1.2-2.491.vl6.6",
        "qemu-kvm-0.12.1.2-2.491.vl6.6",
        "qemu-kvm-tools-0.12.1.2-2.491.vl6.6"];

foreach (pkg in pkgs)
  if (rpm_check(release:"Virtuozzo-6", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-guest-agent / qemu-img / qemu-kvm / etc");
}
