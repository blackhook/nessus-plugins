#
# (C) Tenable Network Security, Inc.
#


# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2020-1.0-0293. The text
# itself is copyright (C) VMware, Inc.

include('compat.inc');

if (description)
{
  script_id(136550);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/17");

  script_cve_id("CVE-2020-10711");

  script_name(english:"Photon OS 1.0: Linux PHSA-2020-1.0-0293");

  script_set_attribute(attribute:"synopsis", value:
"The remote PhotonOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"An update of the linux package has been released.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vmware/photon/wiki/Security-Updates-1.0-293.md");
  script_set_attribute(attribute:"solution", value:
"Update the affected Linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10711");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:photonos:1.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"PhotonOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "PhotonOS", cpu);

flag = 0;

if (rpm_check(release:"PhotonOS-1.0", cpu:"x86_64", reference:"linux-4.4.221-2.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", cpu:"x86_64", reference:"linux-dev-4.4.221-2.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", cpu:"x86_64", reference:"linux-docs-4.4.221-2.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", cpu:"x86_64", reference:"linux-drivers-gpu-4.4.221-2.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", cpu:"x86_64", reference:"linux-esx-4.4.221-3.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", cpu:"x86_64", reference:"linux-esx-devel-4.4.221-3.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", cpu:"x86_64", reference:"linux-esx-docs-4.4.221-3.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", cpu:"x86_64", reference:"linux-oprofile-4.4.221-2.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", cpu:"x86_64", reference:"linux-sound-4.4.221-2.ph1")) flag++;
if (rpm_check(release:"PhotonOS-1.0", cpu:"x86_64", reference:"linux-tools-4.4.221-2.ph1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux");
}
