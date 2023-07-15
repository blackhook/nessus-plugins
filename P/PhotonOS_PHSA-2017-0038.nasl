#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2/7/2019
#

# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2017-0038. The text
# itself is copyright (C) VMware, Inc.

include("compat.inc");

if (description)
{
  script_id(111887);
  script_version("1.2");
  script_cvs_date("Date: 2019/02/07 18:59:50");

  script_cve_id(
    "CVE-2017-0379",
    "CVE-2017-7507",
    "CVE-2017-7529",
    "CVE-2017-7687",
    "CVE-2017-10790",
    "CVE-2017-11462",
    "CVE-2017-11472",
    "CVE-2017-12154",
    "CVE-2017-12799",
    "CVE-2017-13704",
    "CVE-2017-13728",
    "CVE-2017-14729",
    "CVE-2017-14745",
    "CVE-2017-14867",
    "CVE-2017-15020",
    "CVE-2017-1000116",
    "CVE-2017-1000381"
  );

  script_name(english:"Photon OS 1.0: Binutils / C / Dnsmasq / Git / Gnutls / Krb5 / Linux / Mercurial / Mesos / Nginx PHSA-2017-0038 (deprecated)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"An update of [gnutls, c-ares, nginx, mercurial, linux, mesos, git,
binutils, krb5, dnsmasq] packages for PhotonOS has been released.");
  # https://github.com/vmware/photon/wiki/Security-Updates-78
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?12da2a77");
  script_set_attribute(attribute:"solution", value:"n/a.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-14867");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:dnsmasq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:mercurial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:mesos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:nginx");
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
  "binutils-2.29.1-1.ph1",
  "binutils-debuginfo-2.29.1-1.ph1",
  "binutils-devel-2.29.1-1.ph1",
  "c-ares-1.12.0-2.ph1",
  "c-ares-debuginfo-1.12.0-2.ph1",
  "c-ares-devel-1.12.0-2.ph1",
  "dnsmasq-2.76-3.ph1",
  "dnsmasq-debuginfo-2.76-3.ph1",
  "git-2.14.2-1.ph1",
  "git-debuginfo-2.14.2-1.ph1",
  "git-lang-2.14.2-1.ph1",
  "gnutls-3.5.15-1.ph1",
  "gnutls-debuginfo-3.5.15-1.ph1",
  "gnutls-devel-3.5.15-1.ph1",
  "krb5-1.15.2-1.ph1",
  "krb5-debuginfo-1.15.2-1.ph1",
  "linux-4.4.92-1.ph1",
  "linux-api-headers-4.4.92-1.ph1",
  "linux-debuginfo-4.4.92-1.ph1",
  "linux-dev-4.4.92-1.ph1",
  "linux-docs-4.4.92-1.ph1",
  "linux-drivers-gpu-4.4.92-1.ph1",
  "linux-esx-4.4.92-2.ph1",
  "linux-esx-debuginfo-4.4.92-2.ph1",
  "linux-esx-devel-4.4.92-2.ph1",
  "linux-esx-docs-4.4.92-2.ph1",
  "linux-oprofile-4.4.92-1.ph1",
  "linux-sound-4.4.92-1.ph1",
  "linux-tools-4.4.92-1.ph1",
  "mercurial-4.3.3-1.ph1",
  "mercurial-debuginfo-4.3.3-1.ph1",
  "mesos-1.2.2-1.ph1",
  "mesos-debuginfo-1.2.2-1.ph1",
  "mesos-devel-1.2.2-1.ph1",
  "mesos-python-1.2.2-1.ph1",
  "nginx-1.11.13-4.ph1",
  "nginx-debuginfo-1.11.13-4.ph1"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "binutils / c / dnsmasq / git / gnutls / krb5 / linux / mercurial / mesos / nginx");
}
