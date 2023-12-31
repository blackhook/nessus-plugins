#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-62ac1230f7.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(97865);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2016-10155", "CVE-2017-2615", "CVE-2017-2620", "CVE-2017-5525", "CVE-2017-5526", "CVE-2017-5552", "CVE-2017-5667", "CVE-2017-5856", "CVE-2017-5857", "CVE-2017-5898", "CVE-2017-5987", "CVE-2017-6505");
  script_xref(name:"FEDORA", value:"2017-62ac1230f7");
  script_xref(name:"IAVB", value:"2017-B-0024-S");

  script_name(english:"Fedora 24 : 2:qemu (2017-62ac1230f7)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - CVE-2017-5525: audio: memory leakage in ac97 (bz
    #1414110)

  - CVE-2017-5526: audio: memory leakage in es1370 (bz
    #1414210)

  - CVE-2016-10155 watchdog: memory leakage in i6300esb (bz
    #1415200)

  - CVE-2017-5552: virtio-gpu-3d: memory leakage (bz
    #1415283)

  - CVE-2017-5667: sd: sdhci OOB access during multi block
    transfer (bz #1417560)

  - CVE-2017-5857: virtio-gpu-3d: host memory leakage in
    virgl_cmd_resource_unref (bz #1418383)

  - CVE-2017-5856: scsi: megasas: memory leakage (bz
    #1418344)

  - CVE-2017-5898: usb: integer overflow in
    emulated_apdu_from_guest (bz #1419700)

  - CVE-2017-5987: sd: infinite loop issue in multi block
    transfers (bz #1422001)

  - CVE-2017-6505: usb: an infinite loop issue in
    ohci_service_ed_list (bz #1429434)

  - CVE-2017-2615: cirrus: oob access while doing bitblt
    copy backward (bz #1418206)

  - CVE-2017-2620: cirrus: potential arbitrary code
    execution (bz #1425419)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-62ac1230f7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected 2:qemu package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:2:qemu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:24");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^24([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 24", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC24", reference:"qemu-2.6.2-7.fc24", epoch:"2")) flag++;


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
