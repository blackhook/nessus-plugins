#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-f941184db1.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102008);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2016-9603", "CVE-2017-10806", "CVE-2017-7377", "CVE-2017-7718", "CVE-2017-7980", "CVE-2017-8112", "CVE-2017-8309", "CVE-2017-8379", "CVE-2017-8380", "CVE-2017-9060", "CVE-2017-9310", "CVE-2017-9330", "CVE-2017-9374");
  script_xref(name:"FEDORA", value:"2017-f941184db1");

  script_name(english:"Fedora 25 : 2:qemu (2017-f941184db1)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - CVE-2017-7718: cirrus: OOB read access issue (bz
    #1443443)

  - CVE-2016-9603: cirrus: heap buffer overflow via vnc
    connection (bz #1432040)

  - CVE-2017-7377: 9pfs: fix file descriptor leak (bz
    #1437872)

  - CVE-2017-7980: cirrus: OOB r/w access issues in bitblt
    (bz #1444372)

  - CVE-2017-8112: vmw_pvscsi: infinite loop in pvscsi_log2
    (bz #1445622)

  - CVE-2017-8309: audio: host memory lekage via capture
    buffer (bz #1446520)

  - CVE-2017-8379: input: host memory lekage via keyboard
    events (bz #1446560)

  - CVE-2017-8380: scsi: megasas: out-of-bounds read in
    megasas_mmio_write (bz #1446578)

  - CVE-2017-9060: virtio-gpu: host memory leakage in Virtio
    GPU device (bz #1452598)

  - CVE-2017-9310: net: infinite loop in e1000e NIC
    emulation (bz #1452623)

  - CVE-2017-9330: usb: ohci: infinite loop due to incorrect
    return value (bz #1457699)

  - CVE-2017-9374: usb: ehci host memory leakage during
    hotunplug (bz #1459137)

  - CVE-2017-10806: usb-redirect: stack-based buffer
    overflow in debug logging (bz #1468497)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-f941184db1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected 2:qemu package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:2:qemu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:25");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^25([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 25", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC25", reference:"qemu-2.7.1-7.fc25", epoch:"2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "2:qemu");
}
