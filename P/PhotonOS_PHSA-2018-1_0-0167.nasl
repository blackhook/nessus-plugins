#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2/7/2019
#

# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2018-1.0-0167. The text
# itself is copyright (C) VMware, Inc.

include("compat.inc");

if (description)
{
  script_id(111946);
  script_version("1.3");
  script_cvs_date("Date: 2019/04/05 23:25:07");

  script_cve_id(
    "CVE-2017-11423",
    "CVE-2017-1000382",
    "CVE-2018-1049",
    "CVE-2018-2938",
    "CVE-2018-2940",
    "CVE-2018-2941",
    "CVE-2018-2942",
    "CVE-2018-2964",
    "CVE-2018-2972",
    "CVE-2018-2973",
    "CVE-2018-6797",
    "CVE-2018-6798",
    "CVE-2018-6913",
    "CVE-2018-7182",
    "CVE-2018-7183",
    "CVE-2018-7184",
    "CVE-2018-7185",
    "CVE-2018-10689"
  );

  script_name(english:"Photon OS 1.0: Blktrace / Libmspack / Ntp / Openjdk / Perl / Systemd / Vim PHSA-2018-1.0-0167 (deprecated)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"An update of 'vim', 'ntp', 'openjdk', 'libmspack', 'blktrace',
'systemd', 'perl' packages of Photon OS has been released.");
  # https://github.com/vmware/photon/wiki/Security-Updates-1.0-167
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8b270eb8");
  script_set_attribute(attribute:"solution", value:"n/a.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6797");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:blktrace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:libmspack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:vim");
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
  "blktrace-1.1.0-3.ph1",
  "blktrace-debuginfo-1.1.0-3.ph1",
  "libmspack-0.5alpha-4.ph1",
  "libmspack-debuginfo-0.5alpha-4.ph1",
  "ntp-4.2.8p11-1.ph1",
  "ntp-debuginfo-4.2.8p11-1.ph1",
  "openjdk-1.8.0.181-1.ph1",
  "openjdk-debuginfo-1.8.0.181-1.ph1",
  "openjdk-doc-1.8.0.181-1.ph1",
  "openjdk-sample-1.8.0.181-1.ph1",
  "openjdk-src-1.8.0.181-1.ph1",
  "perl-5.24.1-1.ph1",
  "perl-CGI-4.26-3.ph1",
  "perl-Config-IniFiles-2.88-3.ph1",
  "perl-Crypt-SSLeay-0.72-2.ph1",
  "perl-DBD-SQLite-1.50-6.ph1",
  "perl-DBD-SQLite-debuginfo-1.50-6.ph1",
  "perl-DBI-1.634-3.ph1",
  "perl-DBI-debuginfo-1.634-3.ph1",
  "perl-DBIx-Simple-1.35-3.ph1",
  "perl-Exporter-Tiny-0.042-3.ph1",
  "perl-File-HomeDir-1.00-3.ph1",
  "perl-File-Which-1.21-3.ph1",
  "perl-IO-Socket-SSL-2.024-3.ph1",
  "perl-JSON-Any-1.39-3.ph1",
  "perl-JSON-XS-3.01-3.ph1",
  "perl-JSON-XS-debuginfo-3.01-3.ph1",
  "perl-List-MoreUtils-0.413-3.ph1",
  "perl-List-MoreUtils-debuginfo-0.413-3.ph1",
  "perl-Module-Build-0.4216-3.ph1",
  "perl-Module-Install-1.16-3.ph1",
  "perl-Module-ScanDeps-1.18-3.ph1",
  "perl-Net-SSLeay-1.72-3.ph1",
  "perl-Net-SSLeay-debuginfo-1.72-3.ph1",
  "perl-Object-Accessor-0.48-3.ph1",
  "perl-Path-Class-0.37-2.ph1",
  "perl-Try-Tiny-0.28-2.ph1",
  "perl-Types-Serialiser-1.0-3.ph1",
  "perl-WWW-Curl-4.17-4.ph1",
  "perl-WWW-Curl-debuginfo-4.17-4.ph1",
  "perl-YAML-1.15-3.ph1",
  "perl-YAML-Tiny-1.69-3.ph1",
  "perl-common-sense-3.74-3.ph1",
  "perl-debuginfo-5.24.1-1.ph1",
  "perl-libintl-1.24-3.ph1",
  "perl-libintl-debuginfo-1.24-3.ph1",
  "systemd-228-47.ph1",
  "systemd-debuginfo-228-47.ph1",
  "vim-7.4-10.ph1",
  "vim-extra-7.4-10.ph1"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "blktrace / libmspack / ntp / openjdk / perl / systemd / vim");
}
