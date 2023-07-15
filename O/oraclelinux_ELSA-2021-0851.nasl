##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-0851.
##

include('compat.inc');

if (description)
{
  script_id(147863);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/19");

  script_cve_id(
    "CVE-2019-10146",
    "CVE-2019-10179",
    "CVE-2019-10221",
    "CVE-2020-1721",
    "CVE-2020-25715",
    "CVE-2021-20179"
  );

  script_name(english:"Oracle Linux 7 : pki-core (ELSA-2021-0851)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2021-0851 advisory.

  - A Reflected Cross Site Scripting flaw was found in all pki-core 10.x.x versions module from the pki-core
    server due to the CA Agent Service not properly sanitizing the certificate request page. An attacker could
    inject a specially crafted value that will be executed on the victim's browser. (CVE-2019-10146)

  - A vulnerability was found in all pki-core 10.x.x versions, where the Key Recovery Authority (KRA) Agent
    Service did not properly sanitize recovery request search page, enabling a Reflected Cross Site Scripting
    (XSS) vulnerability. An attacker could trick an authenticated victim into executing specially crafted
    Javascript code. (CVE-2019-10179)

  - A Reflected Cross Site Scripting vulnerability was found in all pki-core 10.x.x versions, where the pki-ca
    module from the pki-core server. This flaw is caused by missing sanitization of the GET URL parameters. An
    attacker could abuse this flaw to trick an authenticated user into clicking a specially crafted link which
    can execute arbitrary code when viewed in a browser. (CVE-2019-10221)

  - pki-core: KRA vulnerable to reflected XSS via the getPk12 page (CVE-2020-1721)

  - A flaw was found in pki-core. An attacker who has successfully compromised a key could use this flaw to
    renew the corresponding certificate over and over again, as long as it is not explicitly revoked. The
    highest threat from this vulnerability is to data confidentiality and integrity. (CVE-2021-20179)

  - pki-core: XSS in the certificate search results (CVE-2020-25715)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-0851.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20179");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-base-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-kra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-symkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-tools");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

pkgs = [
    {'reference':'pki-base-10.5.18-12.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pki-base-java-10.5.18-12.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pki-ca-10.5.18-12.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pki-javadoc-10.5.18-12.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pki-kra-10.5.18-12.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pki-server-10.5.18-12.el7_9', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pki-symkey-10.5.18-12.el7_9', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pki-symkey-10.5.18-12.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pki-tools-10.5.18-12.el7_9', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pki-tools-10.5.18-12.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  rpm_prefix = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['rpm_prefix'])) rpm_prefix = package_array['rpm_prefix'];
  if (reference && release) {
    if (rpm_prefix) {
        if (rpm_exists(release:release, rpm:rpm_prefix) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'pki-base / pki-base-java / pki-ca / etc');
}