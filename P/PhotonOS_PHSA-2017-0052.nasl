#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2/7/2019
#

# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2017-0052. The text
# itself is copyright (C) VMware, Inc.

include("compat.inc");

if (description)
{
  script_id(111901);
  script_version("1.2");
  script_cvs_date("Date: 2019/02/07 18:59:50");

  script_cve_id(
    "CVE-2016-5417",
    "CVE-2017-15115",
    "CVE-2017-15535",
    "CVE-2017-15906",
    "CVE-2017-16548",
    "CVE-2017-16826",
    "CVE-2017-16827",
    "CVE-2017-16828",
    "CVE-2017-16829",
    "CVE-2017-16830",
    "CVE-2017-16831",
    "CVE-2017-16832",
    "CVE-2017-16844",
    "CVE-2017-1000158",
    "CVE-2017-1000256"
  );

  script_name(english:"Photon OS 1.0: Binutils / Glibc / Linux / Mongodb / Openssh / Procmail / Python2 / Rsync PHSA-2017-0052 (deprecated)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"An update of
[rsync,python2,procmail,libvirt,linux,mongodb,openssh,binutils,glibc]
packages for photonOS has been released.");
  # https://github.com/vmware/photon/wiki/Security-Updates-91
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a72c45fb");
  script_set_attribute(attribute:"solution", value:"n/a.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-16844");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:mongodb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:procmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:python2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:rsync");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:photonos:1.0");
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
if (release !~ "^VMware Photon (?:Linux|OS) 1\.0(\D|$)") audit(AUDIT_OS_NOT, "PhotonOS 1.0");

if (!get_kb_item("Host/PhotonOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "PhotonOS", cpu);

flag = 0;

pkgs = [
  "binutils-2.29.1-2.ph1",
  "binutils-debuginfo-2.29.1-2.ph1",
  "binutils-devel-2.29.1-2.ph1",
  "glibc-2.22-17.ph1",
  "glibc-devel-2.22-17.ph1",
  "glibc-lang-2.22-17.ph1",
  "linux-4.4.103-1.ph1",
  "linux-api-headers-4.4.103-1.ph1",
  "linux-debuginfo-4.4.103-1.ph1",
  "linux-dev-4.4.103-1.ph1",
  "linux-docs-4.4.103-1.ph1",
  "linux-drivers-gpu-4.4.103-1.ph1",
  "linux-esx-4.4.103-1.ph1",
  "linux-esx-debuginfo-4.4.103-1.ph1",
  "linux-esx-devel-4.4.103-1.ph1",
  "linux-esx-docs-4.4.103-1.ph1",
  "linux-oprofile-4.4.103-1.ph1",
  "linux-sound-4.4.103-1.ph1",
  "linux-tools-4.4.103-1.ph1",
  "mongodb-3.4.10-1.ph1",
  "mongodb-debuginfo-3.4.10-1.ph1",
  "openssh-7.4p1-7.ph1",
  "openssh-debuginfo-7.4p1-7.ph1",
  "procmail-3.22-4.ph1",
  "python2-2.7.13-4.ph1",
  "python2-debuginfo-2.7.13-4.ph1",
  "python2-devel-2.7.13-4.ph1",
  "python2-libs-2.7.13-4.ph1",
  "python2-tools-2.7.13-4.ph1",
  "rsync-3.1.2-3.ph1",
  "rsync-debuginfo-3.1.2-3.ph1"
];

foreach (pkg in pkgs)
  if (rpm_check(release:"PhotonOS-1.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "binutils / glibc / linux / mongodb / openssh / procmail / python2 / rsync");
}
