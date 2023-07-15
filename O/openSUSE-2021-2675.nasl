#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:2675-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152552);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2021-27962",
    "CVE-2021-28146",
    "CVE-2021-28147",
    "CVE-2021-28148",
    "CVE-2021-29622"
  );

  script_name(english:"openSUSE 15 Security Update : SUSE Manager Client Tools (openSUSE-SU-2021:2675-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:2675-1 advisory.

  - Grafana Enterprise 7.2.x and 7.3.x before 7.3.10 and 7.4.x before 7.4.5 allows a dashboard editor to
    bypass a permission check concerning a data source they should not be able to access. (CVE-2021-27962)

  - The team sync HTTP API in Grafana Enterprise 7.4.x before 7.4.5 has an Incorrect Access Control issue. On
    Grafana instances using an external authentication service, this vulnerability allows any authenticated
    user to add external groups to existing teams. This can be used to grant a user team permissions that the
    user isn't supposed to have. (CVE-2021-28146)

  - The team sync HTTP API in Grafana Enterprise 6.x before 6.7.6, 7.x before 7.3.10, and 7.4.x before 7.4.5
    has an Incorrect Access Control issue. On Grafana instances using an external authentication service and
    having the EditorsCanAdmin feature enabled, this vulnerability allows any authenticated user to add
    external groups to any existing team. This can be used to grant a user team permissions that the user
    isn't supposed to have. (CVE-2021-28147)

  - One of the usage insights HTTP API endpoints in Grafana Enterprise 6.x before 6.7.6, 7.x before 7.3.10,
    and 7.4.x before 7.4.5 is accessible without any authentication. This allows any unauthenticated user to
    send an unlimited number of requests to the endpoint, leading to a denial of service (DoS) attack against
    a Grafana Enterprise instance. (CVE-2021-28148)

  - Prometheus is an open-source monitoring system and time series database. In 2.23.0, Prometheus changed its
    default UI to the New ui. To ensure a seamless transition, the URL's prefixed by /new redirect to /. Due
    to a bug in the code, it is possible for an attacker to craft an URL that can redirect to any other URL,
    in the /new endpoint. If a user visits a prometheus server with a specially crafted address, they can be
    redirected to an arbitrary URL. The issue was patched in the 2.26.1 and 2.27.1 releases. In 2.28.0, the
    /new endpoint will be removed completely. The workaround is to disable access to /new via a reverse proxy
    in front of Prometheus. (CVE-2021-29622)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1175478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186242");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186508");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186581");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188846");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/X43KWNU2XMSBJQO437DI7TR5WXTEXGK5/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?49baa061");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-27962");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28146");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28147");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28148");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29622");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29622");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-27962");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ansible-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dracut-saltboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mgr-cfg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mgr-cfg-actions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mgr-cfg-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mgr-cfg-management");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mgr-custom-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mgr-osa-dispatcher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mgr-osad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mgr-push");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mgr-virtualization-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-mgr-cfg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-mgr-cfg-actions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-mgr-cfg-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-mgr-cfg-management");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-mgr-osa-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-mgr-osa-dispatcher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-mgr-osad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-mgr-push");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-mgr-virtualization-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-mgr-virtualization-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-rhnlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-spacewalk-check");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-spacewalk-client-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-spacewalk-client-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-spacewalk-koan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-spacewalk-oscap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-suseRegisterInfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-uyuni-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-mgr-cfg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-mgr-cfg-actions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-mgr-cfg-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-mgr-cfg-management");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-mgr-osa-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-mgr-osa-dispatcher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-mgr-osad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-mgr-push");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-mgr-virtualization-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-mgr-virtualization-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-rhnlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-spacewalk-check");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-spacewalk-client-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-spacewalk-client-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-spacewalk-koan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-spacewalk-oscap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-suseRegisterInfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-uyuni-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:spacecmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:spacewalk-check");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:spacewalk-client-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:spacewalk-client-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:spacewalk-koan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:spacewalk-oscap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:suseRegisterInfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'ansible-2.9.21-1.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ansible-test-2.9.21-1.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dracut-saltboot-0.1.1627546504.96a0b3e-1.27.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mgr-cfg-4.2.3-1.18.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mgr-cfg-actions-4.2.3-1.18.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mgr-cfg-client-4.2.3-1.18.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mgr-cfg-management-4.2.3-1.18.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mgr-custom-info-4.2.2-1.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mgr-osa-dispatcher-4.2.6-1.30.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mgr-osad-4.2.6-1.30.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mgr-push-4.2.3-1.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mgr-virtualization-host-4.2.2-1.20.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-mgr-cfg-4.2.3-1.18.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-mgr-cfg-actions-4.2.3-1.18.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-mgr-cfg-client-4.2.3-1.18.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-mgr-cfg-management-4.2.3-1.18.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-mgr-osa-common-4.2.6-1.30.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-mgr-osa-dispatcher-4.2.6-1.30.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-mgr-osad-4.2.6-1.30.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-mgr-push-4.2.3-1.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-mgr-virtualization-common-4.2.2-1.20.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-mgr-virtualization-host-4.2.2-1.20.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-rhnlib-4.2.4-3.28.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-spacewalk-check-4.2.12-3.44.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-spacewalk-client-setup-4.2.12-3.44.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-spacewalk-client-tools-4.2.12-3.44.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-spacewalk-koan-4.2.4-3.21.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-spacewalk-oscap-4.2.2-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-suseRegisterInfo-4.2.4-3.15.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-uyuni-common-libs-4.2.5-1.15.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-mgr-cfg-4.2.3-1.18.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-mgr-cfg-actions-4.2.3-1.18.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-mgr-cfg-client-4.2.3-1.18.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-mgr-cfg-management-4.2.3-1.18.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-mgr-osa-common-4.2.6-1.30.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-mgr-osa-dispatcher-4.2.6-1.30.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-mgr-osad-4.2.6-1.30.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-mgr-push-4.2.3-1.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-mgr-virtualization-common-4.2.2-1.20.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-mgr-virtualization-host-4.2.2-1.20.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-rhnlib-4.2.4-3.28.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-spacewalk-check-4.2.12-3.44.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-spacewalk-client-setup-4.2.12-3.44.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-spacewalk-client-tools-4.2.12-3.44.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-spacewalk-koan-4.2.4-3.21.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-spacewalk-oscap-4.2.2-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-suseRegisterInfo-4.2.4-3.15.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-uyuni-common-libs-4.2.5-1.15.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'spacecmd-4.2.11-3.62.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'spacewalk-check-4.2.12-3.44.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'spacewalk-client-setup-4.2.12-3.44.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'spacewalk-client-tools-4.2.12-3.44.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'spacewalk-koan-4.2.4-3.21.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'spacewalk-oscap-4.2.2-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'suseRegisterInfo-4.2.4-3.15.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ansible / ansible-test / dracut-saltboot / mgr-cfg / mgr-cfg-actions / etc');
}
