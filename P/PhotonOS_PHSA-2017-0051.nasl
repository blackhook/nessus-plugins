#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2/7/2019
#

# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2017-0051. The text
# itself is copyright (C) VMware, Inc.

include("compat.inc");

if (description)
{
  script_id(111900);
  script_version("1.2");
  script_cvs_date("Date: 2019/02/07 18:59:50");

  script_cve_id(
    "CVE-2017-15115",
    "CVE-2017-15906",
    "CVE-2017-16548",
    "CVE-2017-16844",
    "CVE-2017-1000158"
  );

  script_name(english:"Photon OS 2.0: Libvirt / Linux / Openssh / Procmail / Python2 / Rsync PHSA-2017-0051 (deprecated)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"An update of [rsync,linux,openssh,procmail,python2,libvirt] packages
for PhotonOS has been released.");
  # https://github.com/vmware/photon/wiki/Security-Updates-2-5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aca85090");
  script_set_attribute(attribute:"solution", value:"n/a.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-16844");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:procmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:python2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:rsync");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:photonos:2.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"PhotonOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/PhotonOS/release", "Host/PhotonOS/rpm-list");

  exit(0);
}

exit(0, "This plugin has been deprecated.");

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/PhotonOS/release");
if (isnull(release) || release !~ "^VMware Photon") audit(AUDIT_OS_NOT, "PhotonOS");
if (release !~ "^VMware Photon (?:Linux|OS) 2\.0(\D|$)") audit(AUDIT_OS_NOT, "PhotonOS 2.0");

if (!get_kb_item("Host/PhotonOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "PhotonOS", cpu);

flag = 0;

pkgs = [
  "libvirt-3.2.0-3.ph2",
  "libvirt-debuginfo-3.2.0-3.ph2",
  "libvirt-devel-3.2.0-3.ph2",
  "libvirt-docs-3.2.0-3.ph2",
  "linux-4.9.66-2.ph2",
  "linux-api-headers-4.9.66-1.ph2",
  "linux-debuginfo-4.9.66-2.ph2",
  "linux-devel-4.9.66-2.ph2",
  "linux-docs-4.9.66-2.ph2",
  "linux-drivers-gpu-4.9.66-2.ph2",
  "linux-esx-4.9.66-1.ph2",
  "linux-esx-debuginfo-4.9.66-1.ph2",
  "linux-esx-devel-4.9.66-1.ph2",
  "linux-esx-docs-4.9.66-1.ph2",
  "linux-oprofile-4.9.66-2.ph2",
  "linux-secure-4.9.66-1.ph2",
  "linux-secure-debuginfo-4.9.66-1.ph2",
  "linux-secure-devel-4.9.66-1.ph2",
  "linux-secure-docs-4.9.66-1.ph2",
  "linux-secure-lkcm-4.9.66-1.ph2",
  "linux-sound-4.9.66-2.ph2",
  "linux-tools-4.9.66-2.ph2",
  "openssh-7.5p1-10.ph2",
  "openssh-clients-7.5p1-10.ph2",
  "openssh-debuginfo-7.5p1-10.ph2",
  "openssh-server-7.5p1-10.ph2",
  "procmail-3.22-5.ph2",
  "procmail-debuginfo-3.22-5.ph2",
  "python2-2.7.13-11.ph2",
  "python2-debuginfo-2.7.13-11.ph2",
  "python2-devel-2.7.13-11.ph2",
  "python2-libs-2.7.13-11.ph2",
  "python2-test-2.7.13-11.ph2",
  "python2-tools-2.7.13-11.ph2",
  "rsync-3.1.2-4.ph2",
  "rsync-debuginfo-3.1.2-4.ph2"
];

foreach (pkg in pkgs)
  if (rpm_check(release:"PhotonOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt / linux / openssh / procmail / python2 / rsync");
}
