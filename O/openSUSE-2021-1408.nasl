#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:1408-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154766);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/20");

  script_cve_id(
    "CVE-2011-5325",
    "CVE-2018-20679",
    "CVE-2018-1000500",
    "CVE-2018-1000517",
    "CVE-2021-28831"
  );

  script_name(english:"openSUSE 15 Security Update : busybox (openSUSE-SU-2021:1408-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:1408-1 advisory.

  - Directory traversal vulnerability in the BusyBox implementation of tar before 1.22.0 v5 allows remote
    attackers to point to files outside the current working directory via a symlink. (CVE-2011-5325)

  - Busybox contains a Missing SSL certificate validation vulnerability in The busybox wget applet that can
    result in arbitrary code execution. This attack appear to be exploitable via Simply download any file over
    HTTPS using busybox wget https://compromised-domain.com/important-file. (CVE-2018-1000500)

  - BusyBox project BusyBox wget version prior to commit 8e2174e9bd836e53c8b9c6e00d1bc6e2a718686e contains a
    Buffer Overflow vulnerability in Busybox wget that can result in heap buffer overflow. This attack appear
    to be exploitable via network connectivity. This vulnerability appears to have been fixed in after commit
    8e2174e9bd836e53c8b9c6e00d1bc6e2a718686e. (CVE-2018-1000517)

  - An issue was discovered in BusyBox before 1.30.0. An out of bounds read in udhcp components (consumed by
    the DHCP server, client, and relay) allows a remote attacker to leak sensitive information from the stack
    by sending a crafted DHCP message. This is related to verification in udhcp_get_option() in
    networking/udhcp/common.c that 4-byte options are indeed 4 bytes. (CVE-2018-20679)

  - decompress_gunzip.c in BusyBox through 1.32.1 mishandles the error bit on the huft_build result pointer,
    with a resultant invalid free or segmentation fault, via malformed gzip data. (CVE-2021-28831)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/951562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1099260");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1099263");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1121426");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184522");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/LTZHQ6OAWXY23IUCNO7X25C5CHHCWLOM/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0609c5b");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2011-5325");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-1000500");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-1000517");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-20679");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28831");
  script_set_attribute(attribute:"solution", value:
"Update the affected busybox and / or busybox-static packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1000517");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:busybox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:busybox-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.2', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'busybox-1.26.2-lp152.5.3.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'busybox-static-1.26.2-lp152.5.3.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'busybox / busybox-static');
}
