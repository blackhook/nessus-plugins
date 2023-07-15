##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2021-1.0-0364. The text
# itself is copyright (C) VMware, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146877);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/09");

  script_cve_id(
    "CVE-2020-28243",
    "CVE-2020-28972",
    "CVE-2020-35662",
    "CVE-2021-3144",
    "CVE-2021-3148",
    "CVE-2021-3197",
    "CVE-2021-25281",
    "CVE-2021-25282",
    "CVE-2021-25283",
    "CVE-2021-25284"
  );
  script_xref(name:"IAVA", value:"2021-A-0112-S");

  script_name(english:"Photon OS 1.0: Salt3 PHSA-2021-1.0-0364");

  script_set_attribute(attribute:"synopsis", value:
"The remote PhotonOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"An update of the salt3 package has been released.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vmware/photon/wiki/Security-Updates-1.0-364.md");
  script_set_attribute(attribute:"solution", value:
"Update the affected Linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3197");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SaltStack Salt API Unauthenticated RCE through wheel_async client');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:salt3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:photonos:1.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (release !~ "^VMware Photon (?:Linux|OS) 1\.0(\D|$)") audit(AUDIT_OS_NOT, 'PhotonOS 1.0');

if (!get_kb_item('Host/PhotonOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'PhotonOS', cpu);

flag = 0;

if (rpm_check(release:'PhotonOS-1.0', reference:'salt3-2019.2.4-2.ph1')) flag++;
if (rpm_check(release:'PhotonOS-1.0', reference:'salt3-api-2019.2.4-2.ph1')) flag++;
if (rpm_check(release:'PhotonOS-1.0', reference:'salt3-cloud-2019.2.4-2.ph1')) flag++;
if (rpm_check(release:'PhotonOS-1.0', reference:'salt3-master-2019.2.4-2.ph1')) flag++;
if (rpm_check(release:'PhotonOS-1.0', reference:'salt3-minion-2019.2.4-2.ph1')) flag++;
if (rpm_check(release:'PhotonOS-1.0', reference:'salt3-proxy-2019.2.4-2.ph1')) flag++;
if (rpm_check(release:'PhotonOS-1.0', reference:'salt3-spm-2019.2.4-2.ph1')) flag++;
if (rpm_check(release:'PhotonOS-1.0', reference:'salt3-ssh-2019.2.4-2.ph1')) flag++;
if (rpm_check(release:'PhotonOS-1.0', reference:'salt3-syndic-2019.2.4-2.ph1')) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'salt3');
}
