#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2/7/2019
#

# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2017-0029. The text
# itself is copyright (C) VMware, Inc.

include("compat.inc");

if (description)
{
  script_id(111878);
  script_version("1.5");
  script_cvs_date("Date: 2019/04/05 23:25:07");

  script_cve_id(
    "CVE-2017-3161",
    "CVE-2017-3162",
    "CVE-2017-7533",
    "CVE-2017-7542",
    "CVE-2017-8872",
    "CVE-2017-9228",
    "CVE-2017-10911",
    "CVE-2017-1000112"
  );

  script_name(english:"Photon OS 1.0: Cassandra / Libxml2 / Linux / Ruby PHSA-2017-0029 (deprecated)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"An update of [ruby,cassandra,linux,libxml2] packages for PhotonOS has
been released.");
  # https://github.com/vmware/photon/wiki/Security-Updates-62
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f50b0a30");
  script_set_attribute(attribute:"solution", value:"n/a.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3162");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel UDP Fragmentation Offset (UFO) Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:cassandra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:ruby");
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
  "cassandra-3.10-5.ph1",
  "libxml2-2.9.4-7.ph1",
  "libxml2-debuginfo-2.9.4-7.ph1",
  "libxml2-devel-2.9.4-7.ph1",
  "libxml2-python-2.9.4-7.ph1",
  "linux-4.4.82-1.ph1",
  "linux-api-headers-4.4.82-1.ph1",
  "linux-debuginfo-4.4.82-1.ph1",
  "linux-dev-4.4.82-1.ph1",
  "linux-docs-4.4.82-1.ph1",
  "linux-drivers-gpu-4.4.82-1.ph1",
  "linux-esx-4.4.82-1.ph1",
  "linux-esx-debuginfo-4.4.82-1.ph1",
  "linux-esx-devel-4.4.82-1.ph1",
  "linux-esx-docs-4.4.82-1.ph1",
  "linux-oprofile-4.4.82-1.ph1",
  "linux-sound-4.4.82-1.ph1",
  "linux-tools-4.4.82-1.ph1",
  "ruby-2.4.0-5.ph1",
  "ruby-debuginfo-2.4.0-5.ph1"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cassandra / libxml2 / linux / ruby");
}
