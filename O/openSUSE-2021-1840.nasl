#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:1840-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151746);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2021-21341",
    "CVE-2021-21342",
    "CVE-2021-21343",
    "CVE-2021-21344",
    "CVE-2021-21345",
    "CVE-2021-21346",
    "CVE-2021-21347",
    "CVE-2021-21348",
    "CVE-2021-21349",
    "CVE-2021-21350",
    "CVE-2021-21351"
  );

  script_name(english:"openSUSE 15 Security Update : xstream (openSUSE-SU-2021:1840-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:1840-1 advisory.

  - XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.16,
    there is vulnerability which may allow a remote attacker to allocate 100% CPU time on the target system
    depending on CPU type or parallel execution of such a payload resulting in a denial of service only by
    manipulating the processed input stream. No user is affected who followed the recommendation to setup
    XStream's security framework with a whitelist limited to the minimal required types. If you rely on
    XStream's default blacklist of the Security Framework, you will have to use at least version 1.4.16.
    (CVE-2021-21341)

  - XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.16,
    there is a vulnerability where the processed stream at unmarshalling time contains type information to
    recreate the formerly written objects. XStream creates therefore new instances based on these type
    information. An attacker can manipulate the processed input stream and replace or inject objects, that
    result in a server-side forgery request. No user is affected, who followed the recommendation to setup
    XStream's security framework with a whitelist limited to the minimal required types. If you rely on
    XStream's default blacklist of the Security Framework, you will have to use at least version 1.4.16.
    (CVE-2021-21342)

  - XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.16,
    there is a vulnerability where the processed stream at unmarshalling time contains type information to
    recreate the formerly written objects. XStream creates therefore new instances based on these type
    information. An attacker can manipulate the processed input stream and replace or inject objects, that
    result in the deletion of a file on the local host. No user is affected, who followed the recommendation
    to setup XStream's security framework with a whitelist limited to the minimal required types. If you rely
    on XStream's default blacklist of the Security Framework, you will have to use at least version 1.4.16.
    (CVE-2021-21343)

  - XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.16,
    there is a vulnerability which may allow a remote attacker to load and execute arbitrary code from a
    remote host only by manipulating the processed input stream. No user is affected, who followed the
    recommendation to setup XStream's security framework with a whitelist limited to the minimal required
    types. If you rely on XStream's default blacklist of the Security Framework, you will have to use at least
    version 1.4.16. (CVE-2021-21344, CVE-2021-21346, CVE-2021-21347)

  - XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.16,
    there is a vulnerability which may allow a remote attacker who has sufficient rights to execute commands
    of the host only by manipulating the processed input stream. No user is affected, who followed the
    recommendation to setup XStream's security framework with a whitelist limited to the minimal required
    types. If you rely on XStream's default blacklist of the Security Framework, you will have to use at least
    version 1.4.16. (CVE-2021-21345)

  - XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.16,
    there is a vulnerability which may allow a remote attacker to occupy a thread that consumes maximum CPU
    time and will never return. No user is affected, who followed the recommendation to setup XStream's
    security framework with a whitelist limited to the minimal required types. If you rely on XStream's
    default blacklist of the Security Framework, you will have to use at least version 1.4.16.
    (CVE-2021-21348)

  - XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.16,
    there is a vulnerability which may allow a remote attacker to request data from internal resources that
    are not publicly available only by manipulating the processed input stream. No user is affected, who
    followed the recommendation to setup XStream's security framework with a whitelist limited to the minimal
    required types. If you rely on XStream's default blacklist of the Security Framework, you will have to use
    at least version 1.4.16. (CVE-2021-21349)

  - XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.16,
    there is a vulnerability which may allow a remote attacker to execute arbitrary code only by manipulating
    the processed input stream. No user is affected, who followed the recommendation to setup XStream's
    security framework with a whitelist limited to the minimal required types. If you rely on XStream's
    default blacklist of the Security Framework, you will have to use at least version 1.4.16.
    (CVE-2021-21350)

  - XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.16,
    there is a vulnerability may allow a remote attacker to load and execute arbitrary code from a remote host
    only by manipulating the processed input stream. No user is affected, who followed the recommendation to
    setup XStream's security framework with a whitelist limited to the minimal required types. If you rely on
    XStream's default blacklist of the Security Framework, you will have to use at least version 1.4.16.
    (CVE-2021-21351)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184372");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184373");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184374");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184375");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184376");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184377");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184378");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184379");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184380");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184796");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184797");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/APETSNTGJFG76V7J5X4K4LWA77F5743O/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aed25093");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21341");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21342");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21343");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21344");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21345");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21346");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21347");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21348");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21349");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21350");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21351");
  script_set_attribute(attribute:"solution", value:
"Update the affected xstream, xstream-benchmark, xstream-javadoc and / or xstream-parent packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21350");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-21345");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xstream-benchmark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xstream-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xstream-parent");
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
    {'reference':'xstream-1.4.16-3.8.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xstream-benchmark-1.4.16-3.8.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xstream-javadoc-1.4.16-3.8.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xstream-parent-1.4.16-3.8.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'xstream / xstream-benchmark / xstream-javadoc / xstream-parent');
}
