#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:0065-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158575);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/03");

  script_cve_id(
    "CVE-2020-8663",
    "CVE-2020-12603",
    "CVE-2020-12604",
    "CVE-2020-12605",
    "CVE-2020-35471"
  );

  script_name(english:"openSUSE 15 Security Update : envoy-proxy (openSUSE-SU-2022:0065-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:0065-1 advisory.

  - Envoy version 1.14.2, 1.13.2, 1.12.4 or earlier may consume excessive amounts of memory when proxying
    HTTP/2 requests or responses with many small (i.e. 1 byte) data frames. (CVE-2020-12603)

  - Envoy version 1.14.2, 1.13.2, 1.12.4 or earlier is susceptible to increased memory usage in the case where
    an HTTP/2 client requests a large payload but does not send enough window updates to consume the entire
    stream and does not reset the stream. (CVE-2020-12604)

  - Envoy version 1.14.2, 1.13.2, 1.12.4 or earlier may consume excessive amounts of memory when processing
    HTTP/1.1 headers with long field names or requests with long URLs. (CVE-2020-12605)

  - Envoy before 1.16.1 mishandles dropped and truncated datagrams, as demonstrated by a segmentation fault
    for a UDP packet size larger than 1500. (CVE-2020-35471)

  - Envoy version 1.14.2, 1.13.2, 1.12.4 or earlier may exhaust file descriptors and/or memory when accepting
    too many connections. (CVE-2020-8663)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1167073");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1173559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180121");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/WUFXLLYPEPLGLE3CNOENBUDET76YJXPI/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?288dd252");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-12603");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-12604");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-12605");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-35471");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-8663");
  script_set_attribute(attribute:"solution", value:
"Update the affected envoy-proxy and / or envoy-proxy-source packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8663");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:envoy-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:envoy-proxy-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'envoy-proxy-1.14.6-bp153.3.4.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'envoy-proxy-1.14.6-bp153.3.4.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'envoy-proxy-source-1.14.6-bp153.3.4.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'envoy-proxy-source-1.14.6-bp153.3.4.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'envoy-proxy / envoy-proxy-source');
}
