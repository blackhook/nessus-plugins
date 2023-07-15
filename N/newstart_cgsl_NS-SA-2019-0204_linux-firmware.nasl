#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0204. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129919);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2018-5383");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : linux-firmware Vulnerability (NS-SA-2019-0204)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has linux-firmware packages installed that are
affected by a vulnerability:

  - Bluetooth firmware or operating system software drivers
    in macOS versions before 10.13, High Sierra and iOS
    versions before 11.4, and Android versions before the
    2018-06-05 patch may not sufficiently validate elliptic
    curve parameters used to generate public keys during a
    Diffie-Hellman key exchange, which may allow a remote
    attacker to obtain the encryption key used by the
    device. (CVE-2018-5383)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0204");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL linux-firmware packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5383");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "iwl100-firmware-39.31.5.1-72.el7.cgslv5.0.4.gaf514ec.lite",
    "iwl1000-firmware-39.31.5.1-72.el7.cgslv5.0.4.gaf514ec.lite",
    "iwl105-firmware-18.168.6.1-72.el7.cgslv5.0.4.gaf514ec.lite",
    "iwl135-firmware-18.168.6.1-72.el7.cgslv5.0.4.gaf514ec.lite",
    "iwl2000-firmware-18.168.6.1-72.el7.cgslv5.0.4.gaf514ec.lite",
    "iwl2030-firmware-18.168.6.1-72.el7.cgslv5.0.4.gaf514ec.lite",
    "iwl3160-firmware-22.0.7.0-72.el7.cgslv5.0.4.gaf514ec.lite",
    "iwl3945-firmware-15.32.2.9-72.el7.cgslv5.0.4.gaf514ec.lite",
    "iwl4965-firmware-228.61.2.24-72.el7.cgslv5.0.4.gaf514ec.lite",
    "iwl5000-firmware-8.83.5.1_1-72.el7.cgslv5.0.4.gaf514ec.lite",
    "iwl5150-firmware-8.24.2.2-72.el7.cgslv5.0.4.gaf514ec.lite",
    "iwl6000-firmware-9.221.4.1-72.el7.cgslv5.0.4.gaf514ec.lite",
    "iwl6000g2a-firmware-17.168.5.3-72.el7.cgslv5.0.4.gaf514ec.lite",
    "iwl6000g2b-firmware-17.168.5.2-72.el7.cgslv5.0.4.gaf514ec.lite",
    "iwl6050-firmware-41.28.5.1-72.el7.cgslv5.0.4.gaf514ec.lite",
    "iwl7260-firmware-22.0.7.0-72.el7.cgslv5.0.4.gaf514ec.lite",
    "iwl7265-firmware-22.0.7.0-72.el7.cgslv5.0.4.gaf514ec.lite",
    "linux-firmware-20190429-72.gitddde598.el7.cgslv5.0.4.gaf514ec.lite",
    "linux-firmware-core-20190429-72.gitddde598.el7.cgslv5.0.4.gaf514ec.lite",
    "linux-firmware-other-20190429-72.gitddde598.el7.cgslv5.0.4.gaf514ec.lite"
  ],
  "CGSL MAIN 5.04": [
    "iwl100-firmware-39.31.5.1-72.el7.cgslv5",
    "iwl1000-firmware-39.31.5.1-72.el7.cgslv5",
    "iwl105-firmware-18.168.6.1-72.el7.cgslv5",
    "iwl135-firmware-18.168.6.1-72.el7.cgslv5",
    "iwl2000-firmware-18.168.6.1-72.el7.cgslv5",
    "iwl2030-firmware-18.168.6.1-72.el7.cgslv5",
    "iwl3160-firmware-22.0.7.0-72.el7.cgslv5",
    "iwl3945-firmware-15.32.2.9-72.el7.cgslv5",
    "iwl4965-firmware-228.61.2.24-72.el7.cgslv5",
    "iwl5000-firmware-8.83.5.1_1-72.el7.cgslv5",
    "iwl5150-firmware-8.24.2.2-72.el7.cgslv5",
    "iwl6000-firmware-9.221.4.1-72.el7.cgslv5",
    "iwl6000g2a-firmware-17.168.5.3-72.el7.cgslv5",
    "iwl6000g2b-firmware-17.168.5.2-72.el7.cgslv5",
    "iwl6050-firmware-41.28.5.1-72.el7.cgslv5",
    "iwl7260-firmware-22.0.7.0-72.el7.cgslv5",
    "iwl7265-firmware-22.0.7.0-72.el7.cgslv5",
    "linux-firmware-20190429-72.gitddde598.el7.cgslv5"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-firmware");
}
