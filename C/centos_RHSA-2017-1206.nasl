#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1206 and 
# CentOS Errata and Security Advisory 2017:1206 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100068);
  script_version("3.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-9603", "CVE-2017-2633", "CVE-2017-7718", "CVE-2017-7980");
  script_xref(name:"RHSA", value:"2017:1206");

  script_name(english:"CentOS 6 : qemu-kvm (CESA-2017:1206)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for qemu-kvm is now available for Red Hat Enterprise Linux
6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Kernel-based Virtual Machine (KVM) is a full virtualization solution
for Linux on a variety of architectures. The qemu-kvm package provides
the user-space component for running virtual machines that use KVM.

Security Fix(es) :

* A heap buffer overflow flaw was found in QEMU's Cirrus CLGD 54xx VGA
emulator's VNC display driver support; the issue could occur when a
VNC client attempted to update its display after a VGA operation is
performed by a guest. A privileged user/process inside a guest could
use this flaw to crash the QEMU process or, potentially, execute
arbitrary code on the host with privileges of the QEMU process.
(CVE-2016-9603)

* An out-of-bounds r/w access issue was found in QEMU's Cirrus CLGD
54xx VGA Emulator support. The vulnerability could occur while copying
VGA data via various bitblt functions. A privileged user inside a
guest could use this flaw to crash the QEMU process or, potentially,
execute arbitrary code on the host with privileges of the QEMU
process. (CVE-2017-7980)

* An out-of-bounds memory access issue was found in QEMU's VNC display
driver support. The vulnerability could occur while refreshing the VNC
display surface area in the 'vnc_refresh_server_surface'. A
user/process inside a guest could use this flaw to crash the QEMU
process, resulting in a denial of service. (CVE-2017-2633)

* An out-of-bounds access issue was found in QEMU's Cirrus CLGD 54xx
VGA Emulator support. The vulnerability could occur while copying VGA
data using bitblt functions (for example,
cirrus_bitblt_rop_fwd_transp_). A privileged user inside a guest could
use this flaw to crash the QEMU process, resulting in denial of
service. (CVE-2017-7718)

Red Hat would like to thank Jiangxin (PSIRT Huawei Inc.) and Li Qiang
(Qihoo 360 Gear Team) for reporting CVE-2017-7980 and Jiangxin (PSIRT
Huawei Inc.) for reporting CVE-2017-7718."
  );
  # https://lists.centos.org/pipermail/centos-announce/2017-May/022403.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?39a95537"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected qemu-kvm packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-9603");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"qemu-guest-agent-0.12.1.2-2.503.el6_9.3")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"qemu-img-0.12.1.2-2.503.el6_9.3")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"qemu-kvm-0.12.1.2-2.503.el6_9.3")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"qemu-kvm-tools-0.12.1.2-2.503.el6_9.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-guest-agent / qemu-img / qemu-kvm / qemu-kvm-tools");
}
