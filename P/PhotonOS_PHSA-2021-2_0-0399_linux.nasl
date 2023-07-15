#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2021-2.0-0399. The text
# itself is copyright (C) VMware, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153963);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/15");

  script_cve_id("CVE-2020-3702", "CVE-2021-40490");

  script_name(english:"Photon OS 2.0: Linux PHSA-2021-2.0-0399");

  script_set_attribute(attribute:"synopsis", value:
"The remote PhotonOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"An update of the linux package has been released.

  - u'Specifically timed and handcrafted traffic can cause internal errors in a WLAN device that lead to
    improper layer 2 Wi-Fi encryption with a consequent possibility of information disclosure over the air for
    a discrete set of traffic' in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon
    Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Voice & Music, Snapdragon
    Wearables, Snapdragon Wired Infrastructure and Networking in APQ8053, IPQ4019, IPQ8064, MSM8909W,
    MSM8996AU, QCA9531, QCN5502, QCS405, SDX20, SM6150, SM7150 (CVE-2020-3702)

  - A race condition was discovered in ext4_write_inline_data_end in fs/ext4/inline.c in the ext4 subsystem in
    the Linux kernel through 5.13.13. (CVE-2021-40490)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vmware/photon/wiki/Security-Updates-2-399.md");
  script_set_attribute(attribute:"solution", value:
"Update the affected Linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40490");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:photonos:2.0");
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

var release = get_kb_item('Host/PhotonOS/release');
if (isnull(release) || release !~ "^VMware Photon") audit(AUDIT_OS_NOT, 'PhotonOS');
if (release !~ "^VMware Photon (?:Linux|OS) 2\.0(\D|$)") audit(AUDIT_OS_NOT, 'PhotonOS 2.0');

if (!get_kb_item('Host/PhotonOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'PhotonOS', cpu);

var flag = 0;

if (rpm_check(release:'PhotonOS-2.0', cpu:'x86_64', reference:'linux-4.9.283-1.ph2')) flag++;
if (rpm_check(release:'PhotonOS-2.0', reference:'linux-api-headers-4.9.283-1.ph2')) flag++;
if (rpm_check(release:'PhotonOS-2.0', cpu:'x86_64', reference:'linux-aws-4.9.283-1.ph2')) flag++;
if (rpm_check(release:'PhotonOS-2.0', cpu:'x86_64', reference:'linux-aws-devel-4.9.283-1.ph2')) flag++;
if (rpm_check(release:'PhotonOS-2.0', cpu:'x86_64', reference:'linux-aws-docs-4.9.283-1.ph2')) flag++;
if (rpm_check(release:'PhotonOS-2.0', cpu:'x86_64', reference:'linux-aws-drivers-gpu-4.9.283-1.ph2')) flag++;
if (rpm_check(release:'PhotonOS-2.0', cpu:'x86_64', reference:'linux-aws-oprofile-4.9.283-1.ph2')) flag++;
if (rpm_check(release:'PhotonOS-2.0', cpu:'x86_64', reference:'linux-aws-sound-4.9.283-1.ph2')) flag++;
if (rpm_check(release:'PhotonOS-2.0', cpu:'x86_64', reference:'linux-devel-4.9.283-1.ph2')) flag++;
if (rpm_check(release:'PhotonOS-2.0', cpu:'x86_64', reference:'linux-docs-4.9.283-1.ph2')) flag++;
if (rpm_check(release:'PhotonOS-2.0', cpu:'x86_64', reference:'linux-drivers-gpu-4.9.283-1.ph2')) flag++;
if (rpm_check(release:'PhotonOS-2.0', cpu:'x86_64', reference:'linux-esx-4.9.283-1.ph2')) flag++;
if (rpm_check(release:'PhotonOS-2.0', cpu:'x86_64', reference:'linux-esx-devel-4.9.283-1.ph2')) flag++;
if (rpm_check(release:'PhotonOS-2.0', cpu:'x86_64', reference:'linux-esx-docs-4.9.283-1.ph2')) flag++;
if (rpm_check(release:'PhotonOS-2.0', cpu:'x86_64', reference:'linux-oprofile-4.9.283-1.ph2')) flag++;
if (rpm_check(release:'PhotonOS-2.0', cpu:'x86_64', reference:'linux-secure-4.9.283-1.ph2')) flag++;
if (rpm_check(release:'PhotonOS-2.0', cpu:'x86_64', reference:'linux-secure-devel-4.9.283-1.ph2')) flag++;
if (rpm_check(release:'PhotonOS-2.0', cpu:'x86_64', reference:'linux-secure-docs-4.9.283-1.ph2')) flag++;
if (rpm_check(release:'PhotonOS-2.0', cpu:'x86_64', reference:'linux-secure-lkcm-4.9.283-1.ph2')) flag++;
if (rpm_check(release:'PhotonOS-2.0', cpu:'x86_64', reference:'linux-sound-4.9.283-1.ph2')) flag++;
if (rpm_check(release:'PhotonOS-2.0', cpu:'x86_64', reference:'linux-tools-4.9.283-1.ph2')) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux');
}
