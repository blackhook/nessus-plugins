#
# (C) Tenable Network Security, Inc.
#


# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2018-1.0-0167. The text
# itself is copyright (C) VMware, Inc.


include('compat.inc');

if (description)
{
  script_id(121865);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2019/03/08");

  script_cve_id("CVE-2018-6797", "CVE-2018-6798", "CVE-2018-6913");

  script_name(english:"Photon OS 1.0: Perl PHSA-2018-1.0-0167");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote PhotonOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"An update of the perl package has been released.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vmware/photon/wiki/Security-Updates-1.0-167.md");
  script_set_attribute(attribute:"solution", value:
"Update the affected Linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6913");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:photonos:1.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"PhotonOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/PhotonOS/release", "Host/PhotonOS/rpm-list");

  exit(0);
}

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

if (rpm_check(release:"PhotonOS-1.0", reference:"perl-5.24.1-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"perl-CGI-4.26-3.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"perl-Config-IniFiles-2.88-3.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"perl-Crypt-SSLeay-0.72-2.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"perl-DBD-SQLite-1.50-6.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"perl-DBD-SQLite-debuginfo-1.50-6.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"perl-DBI-1.634-3.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"perl-DBI-debuginfo-1.634-3.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"perl-DBIx-Simple-1.35-3.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"perl-Exporter-Tiny-0.042-3.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"perl-File-HomeDir-1.00-3.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"perl-File-Which-1.21-3.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"perl-IO-Socket-SSL-2.024-3.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"perl-JSON-Any-1.39-3.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"perl-JSON-XS-3.01-3.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"perl-JSON-XS-debuginfo-3.01-3.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"perl-List-MoreUtils-0.413-3.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"perl-List-MoreUtils-debuginfo-0.413-3.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"perl-Module-Build-0.4216-3.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"perl-Module-Install-1.16-3.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"perl-Module-ScanDeps-1.18-3.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"perl-Net-SSLeay-1.72-3.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"perl-Net-SSLeay-debuginfo-1.72-3.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"perl-Object-Accessor-0.48-3.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"perl-Path-Class-0.37-2.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"perl-Try-Tiny-0.28-2.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"perl-Types-Serialiser-1.0-3.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"perl-WWW-Curl-4.17-4.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"perl-WWW-Curl-debuginfo-4.17-4.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"perl-YAML-1.15-3.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"perl-YAML-Tiny-1.69-3.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"perl-common-sense-3.74-3.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"perl-debuginfo-5.24.1-1.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"perl-libintl-1.24-3.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", reference:"perl-libintl-debuginfo-1.24-3.ph1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl");
}
