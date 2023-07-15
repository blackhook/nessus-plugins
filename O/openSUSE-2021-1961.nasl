#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:1961-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151713);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/16");

  script_cve_id(
    "CVE-2020-25097",
    "CVE-2021-28651",
    "CVE-2021-28652",
    "CVE-2021-28662",
    "CVE-2021-31806"
  );
  script_xref(name:"IAVB", value:"2021-B-0021");

  script_name(english:"openSUSE 15 Security Update : squid (openSUSE-SU-2021:1961-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has a package installed that is affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:1961-1 advisory.

  - An issue was discovered in Squid through 4.13 and 5.x through 5.0.4. Due to improper input validation, it
    allows a trusted client to perform HTTP Request Smuggling and access services otherwise forbidden by the
    security controls. This occurs for certain uri_whitespace configuration settings. (CVE-2020-25097)

  - An issue was discovered in Squid before 4.15 and 5.x before 5.0.6. Due to a buffer-management bug, it
    allows a denial of service. When resolving a request with the urn: scheme, the parser leaks a small amount
    of memory. However, there is an unspecified attack methodology that can easily trigger a large amount of
    memory consumption. (CVE-2021-28651)

  - An issue was discovered in Squid before 4.15 and 5.x before 5.0.6. Due to incorrect parser validation, it
    allows a Denial of Service attack against the Cache Manager API. This allows a trusted client to trigger
    memory leaks that. over time, lead to a Denial of Service via an unspecified short query string. This
    attack is limited to clients with Cache Manager API access privilege. (CVE-2021-28652)

  - An issue was discovered in Squid 4.x before 4.15 and 5.x before 5.0.6. If a remote server sends a certain
    response header over HTTP or HTTPS, there is a denial of service. This header can plausibly occur in
    benign network traffic. (CVE-2021-28662)

  - An issue was discovered in Squid before 4.15 and 5.x before 5.0.6. Due to a memory-management bug, it is
    vulnerable to a Denial of Service attack (against all clients using the proxy) via HTTP Range request
    processing. (CVE-2021-31806)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1171164");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1171569");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185916");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185918");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185919");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185921");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185923");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/PR56WJLXVU76BKBW5SFENNPKF5TJSS5K/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?85974992");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25097");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28651");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28652");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28662");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-31806");
  script_set_attribute(attribute:"solution", value:
"Update the affected squid package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25097");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:squid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

pkgs = [
    {'reference':'squid-4.15-5.26.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  cpu = NULL;
  rpm_spec_vers_cmp = NULL;
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'squid');
}
