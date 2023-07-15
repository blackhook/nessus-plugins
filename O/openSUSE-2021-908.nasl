#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:0908-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151068);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id(
    "CVE-2020-13950",
    "CVE-2020-35452",
    "CVE-2021-26690",
    "CVE-2021-26691",
    "CVE-2021-30641",
    "CVE-2021-31618"
  );
  script_xref(name:"IAVA", value:"2021-A-0259-S");

  script_name(english:"openSUSE 15 Security Update : apache2 (openSUSE-SU-2021:0908-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:0908-1 advisory.

  - Apache HTTP Server versions 2.4.41 to 2.4.46 mod_proxy_http can be made to crash (NULL pointer
    dereference) with specially crafted requests using both Content-Length and Transfer-Encoding headers,
    leading to a Denial of Service (CVE-2020-13950)

  - Apache HTTP Server versions 2.4.0 to 2.4.46 A specially crafted Digest nonce can cause a stack overflow in
    mod_auth_digest. There is no report of this overflow being exploitable, nor the Apache HTTP Server team
    could create one, though some particular compiler and/or compilation option might make it possible, with
    limited consequences anyway due to the size (a single byte) and the value (zero byte) of the overflow
    (CVE-2020-35452)

  - Apache HTTP Server versions 2.4.0 to 2.4.46 A specially crafted Cookie header handled by mod_session can
    cause a NULL pointer dereference and crash, leading to a possible Denial Of Service (CVE-2021-26690)

  - In Apache HTTP Server versions 2.4.0 to 2.4.46 a specially crafted SessionHeader sent by an origin server
    could cause a heap overflow (CVE-2021-26691)

  - Apache HTTP Server versions 2.4.39 to 2.4.46 Unexpected matching behavior with 'MergeSlashes OFF'
    (CVE-2021-30641)

  - Apache HTTP Server protocol handler for the HTTP/2 protocol checks received request headers against the
    size limitations as configured for the server and used for the HTTP/1 protocol as well. On violation of
    these restrictions and HTTP response is sent to the client with a status code indicating why the request
    was rejected. This rejection response was not fully initialised in the HTTP/2 protocol handler if the
    offending header was the very first one received or appeared in a a footer. This led to a NULL pointer
    dereference on initialised memory, crashing reliably the child process. Since such a triggering HTTP/2
    request is easy to craft and submit, this can be exploited to DoS the server. This issue affected
    mod_http2 1.15.17 and Apache HTTP Server version 2.4.47 only. Apache HTTP Server 2.4.47 was never
    released. (CVE-2021-31618)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186922");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186923");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186924");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187017");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187040");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187174");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/F32WQ7K6A45WOBEDFMGMRXDC2F2SL3IF/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?043bab94");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-13950");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-35452");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-26690");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-26691");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30641");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-31618");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26691");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-event");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-example-pages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-worker");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.2', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

pkgs = [
    {'reference':'apache2-2.4.43-lp152.2.15.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apache2-devel-2.4.43-lp152.2.15.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apache2-event-2.4.43-lp152.2.15.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apache2-example-pages-2.4.43-lp152.2.15.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apache2-prefork-2.4.43-lp152.2.15.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apache2-utils-2.4.43-lp152.2.15.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apache2-worker-2.4.43-lp152.2.15.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apache2 / apache2-devel / apache2-event / apache2-example-pages / etc');
}
