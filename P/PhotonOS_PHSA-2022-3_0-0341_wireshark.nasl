#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2022-3.0-0341. The text
# itself is copyright (C) VMware, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156582);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/24");

  script_cve_id(
    "CVE-2021-39920",
    "CVE-2021-39921",
    "CVE-2021-39922",
    "CVE-2021-39923",
    "CVE-2021-39924",
    "CVE-2021-39925",
    "CVE-2021-39926",
    "CVE-2021-39928",
    "CVE-2021-39929"
  );
  script_xref(name:"IAVB", value:"2021-B-0065-S");

  script_name(english:"Photon OS 3.0: Wireshark PHSA-2022-3.0-0341");

  script_set_attribute(attribute:"synopsis", value:
"The remote PhotonOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"An update of the wireshark package has been released.

  - Uncontrolled Recursion in the Bluetooth DHT dissector in Wireshark 3.4.0 to 3.4.9 and 3.2.0 to 3.2.17
    allows denial of service via packet injection or crafted capture file (CVE-2021-39929)

  - NULL pointer exception in the IPPUSB dissector in Wireshark 3.4.0 to 3.4.9 allows denial of service via
    packet injection or crafted capture file (CVE-2021-39920)

  - NULL pointer exception in the Modbus dissector in Wireshark 3.4.0 to 3.4.9 and 3.2.0 to 3.2.17 allows
    denial of service via packet injection or crafted capture file (CVE-2021-39921)

  - Buffer overflow in the C12.22 dissector in Wireshark 3.4.0 to 3.4.9 and 3.2.0 to 3.2.17 allows denial of
    service via packet injection or crafted capture file (CVE-2021-39922)

  - Large loop in the PNRP dissector in Wireshark 3.4.0 to 3.4.9 and 3.2.0 to 3.2.17 allows denial of service
    via packet injection or crafted capture file (CVE-2021-39923)");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vmware/photon/wiki/Security-Updates-3.0-341.md");
  script_set_attribute(attribute:"solution", value:
"Update the affected Linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39929");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:wireshark");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:photonos:3.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"PhotonOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/PhotonOS/release", "Host/PhotonOS/rpm-list");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/PhotonOS/release');
if (isnull(release) || release !~ "^VMware Photon") audit(AUDIT_OS_NOT, 'PhotonOS');
if (release !~ "^VMware Photon (?:Linux|OS) 3\.0(\D|$)") audit(AUDIT_OS_NOT, 'PhotonOS 3.0');

if (!get_kb_item('Host/PhotonOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'PhotonOS', cpu);

var flag = 0;

if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'wireshark-3.6.0-1.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'wireshark-devel-3.6.0-1.ph3')) flag++;

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'wireshark');
}
