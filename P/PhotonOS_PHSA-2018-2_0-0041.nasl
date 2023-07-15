#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2/7/2019
#

# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2018-2.0-0041. The text
# itself is copyright (C) VMware, Inc.

include("compat.inc");

if (description)
{
  script_id(111300);
  script_version("1.2");
  script_cvs_date("Date: 2019/02/07 18:59:50");

  script_cve_id(
    "CVE-2018-1092",
    "CVE-2018-1094",
    "CVE-2018-5764",
    "CVE-2018-7262"
  );
  script_bugtraq_id(102803);

  script_name(english:"Photon OS 2.0 : ceph / linux-esx / rsync / linux / linux-secure / linux-aws (PhotonOS-PHSA-2018-2.0-0041) (deprecated)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"An update of {'ceph', 'linux-esx', 'rsync', 'linux', 'linux-secure',
'linux-aws'} packages of Photon OS has been released.");
  # https://github.com/vmware/photon/wiki/Security-Updates-2-41
    script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?05d8d84b");
  script_set_attribute(attribute:"solution", value:"n/a.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1092");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:rsync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:libceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:python3");
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
  "ceph-12.2.4-1.ph2",
  "ceph-base-12.2.4-1.ph2",
  "ceph-common-12.2.4-1.ph2",
  "ceph-fuse-12.2.4-1.ph2",
  "ceph-mds-12.2.4-1.ph2",
  "ceph-mgr-12.2.4-1.ph2",
  "ceph-mon-12.2.4-1.ph2",
  "ceph-osd-12.2.4-1.ph2",
  "ceph-radosgw-12.2.4-1.ph2",
  "libceph-common-12.2.4-1.ph2",
  "linux-4.9.97-1.ph2",
  "linux-api-headers-4.9.97-1.ph2",
  "linux-aws-4.9.97-1.ph2",
  "linux-aws-4.9.97-1.ph2",
  "linux-aws-debuginfo-4.9.97-1.ph2",
  "linux-aws-debuginfo-4.9.97-1.ph2",
  "linux-aws-devel-4.9.97-1.ph2",
  "linux-aws-devel-4.9.97-1.ph2",
  "linux-aws-docs-4.9.97-1.ph2",
  "linux-aws-docs-4.9.97-1.ph2",
  "linux-aws-drivers-gpu-4.9.97-1.ph2",
  "linux-aws-drivers-gpu-4.9.97-1.ph2",
  "linux-aws-oprofile-4.9.97-1.ph2",
  "linux-aws-oprofile-4.9.97-1.ph2",
  "linux-aws-sound-4.9.97-1.ph2",
  "linux-aws-sound-4.9.97-1.ph2",
  "linux-aws-tools-4.9.97-1.ph2",
  "linux-aws-tools-4.9.97-1.ph2",
  "linux-debuginfo-4.9.97-1.ph2",
  "linux-devel-4.9.97-1.ph2",
  "linux-docs-4.9.97-1.ph2",
  "linux-drivers-gpu-4.9.97-1.ph2",
  "linux-esx-4.9.97-1.ph2",
  "linux-esx-4.9.97-1.ph2",
  "linux-esx-debuginfo-4.9.97-1.ph2",
  "linux-esx-debuginfo-4.9.97-1.ph2",
  "linux-esx-devel-4.9.97-1.ph2",
  "linux-esx-devel-4.9.97-1.ph2",
  "linux-esx-docs-4.9.97-1.ph2",
  "linux-esx-docs-4.9.97-1.ph2",
  "linux-oprofile-4.9.97-1.ph2",
  "linux-secure-4.9.97-1.ph2",
  "linux-secure-4.9.97-1.ph2",
  "linux-secure-debuginfo-4.9.97-1.ph2",
  "linux-secure-debuginfo-4.9.97-1.ph2",
  "linux-secure-devel-4.9.97-1.ph2",
  "linux-secure-devel-4.9.97-1.ph2",
  "linux-secure-docs-4.9.97-1.ph2",
  "linux-secure-docs-4.9.97-1.ph2",
  "linux-secure-lkcm-4.9.97-1.ph2",
  "linux-secure-lkcm-4.9.97-1.ph2",
  "linux-sound-4.9.97-1.ph2",
  "linux-tools-4.9.97-1.ph2",
  "python-ceph-compat-12.2.4-1.ph2",
  "python3-ceph-argparse-12.2.4-1.ph2",
  "rsync-3.1.3-1.ph2",
  "rsync-debuginfo-3.1.3-1.ph2"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux / ceph / rsync / python / libceph / python3");
}
