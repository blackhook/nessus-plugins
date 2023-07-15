#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2021-3.0-0244. The text
# itself is copyright (C) VMware, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(150067);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/10");

  script_cve_id("CVE-2021-25217");

  script_name(english:"Photon OS 3.0: Dhcp PHSA-2021-3.0-0244");

  script_set_attribute(attribute:"synopsis", value:
"The remote PhotonOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"An update of the dhcp package has been released.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vmware/photon/wiki/Security-Updates-3.0-244.md");
  script_set_attribute(attribute:"solution", value:
"Update the affected Linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25217");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:dhcp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:photonos:3.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"PhotonOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/PhotonOS/release", "Host/PhotonOS/rpm-list");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item('Host/PhotonOS/release');
if (isnull(release) || release !~ "^VMware Photon") audit(AUDIT_OS_NOT, 'PhotonOS');
if (release !~ "^VMware Photon (?:Linux|OS) 3\.0(\D|$)") audit(AUDIT_OS_NOT, 'PhotonOS 3.0');

if (!get_kb_item('Host/PhotonOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'PhotonOS', cpu);

flag = 0;

if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'dhcp-client-4.3.5-8.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'dhcp-devel-4.3.5-8.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'dhcp-libs-4.3.5-8.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'dhcp-server-4.3.5-8.ph3')) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dhcp');
}