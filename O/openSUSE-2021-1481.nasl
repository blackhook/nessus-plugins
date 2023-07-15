#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:1481-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155621);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/19");

  script_cve_id(
    "CVE-2020-21529",
    "CVE-2020-21530",
    "CVE-2020-21531",
    "CVE-2020-21532",
    "CVE-2020-21533",
    "CVE-2020-21534",
    "CVE-2020-21535",
    "CVE-2020-21680",
    "CVE-2020-21681",
    "CVE-2020-21682",
    "CVE-2020-21683",
    "CVE-2021-32280"
  );

  script_name(english:"openSUSE 15 Security Update : transfig (openSUSE-SU-2021:1481-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has a package installed that is affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:1481-1 advisory.

  - fig2dev 3.2.7b contains a stack buffer overflow in the bezier_spline function in genepic.c.
    (CVE-2020-21529)

  - fig2dev 3.2.7b contains a segmentation fault in the read_objects function in read.c. (CVE-2020-21530)

  - fig2dev 3.2.7b contains a global buffer overflow in the conv_pattern_index function in gencgm.c.
    (CVE-2020-21531)

  - fig2dev 3.2.7b contains a global buffer overflow in the setfigfont function in genepic.c. (CVE-2020-21532)

  - fig2dev 3.2.7b contains a stack buffer overflow in the read_textobject function in read.c.
    (CVE-2020-21533)

  - fig2dev 3.2.7b contains a global buffer overflow in the get_line function in read.c. (CVE-2020-21534)

  - fig2dev 3.2.7b contains a segmentation fault in the gencgm_start function in gencgm.c. (CVE-2020-21535)

  - A stack-based buffer overflow in the put_arrow() component in genpict2e.c of fig2dev 3.2.7b allows
    attackers to cause a denial of service (DOS) via converting a xfig file into pict2e format.
    (CVE-2020-21680)

  - A global buffer overflow in the set_color component in genge.c of fig2dev 3.2.7b allows attackers to cause
    a denial of service (DOS) via converting a xfig file into ge format. (CVE-2020-21681)

  - A global buffer overflow in the set_fill component in genge.c of fig2dev 3.2.7b allows attackers to cause
    a denial of service (DOS) via converting a xfig file into ge format. (CVE-2020-21682)

  - A global buffer overflow in the shade_or_tint_name_after_declare_color in genpstricks.c of fig2dev 3.2.7b
    allows attackers to cause a denial of service (DOS) via converting a xfig file into pstricks format.
    (CVE-2020-21683)

  - An issue was discovered in fig2dev before 3.2.8.. A NULL pointer dereference exists in the function
    compute_closed_spline() located in trans_spline.c. It allows an attacker to cause Denial of Service. The
    fixed version of fig2dev is 3.2.8. (CVE-2021-32280)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189325");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189343");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189345");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190607");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190616");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190618");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192019");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/2LJVPVAWYSJP4T7SCIWWVBLSRWKCK2EH/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20de1847");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-21529");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-21530");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-21531");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-21532");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-21533");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-21534");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-21535");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-21680");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-21681");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-21682");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-21683");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32280");
  script_set_attribute(attribute:"solution", value:
"Update the affected transfig package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32280");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:transfig");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
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
    {'reference':'transfig-3.2.8b-bp153.3.6.3', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'transfig-3.2.8b-bp153.3.6.3', 'cpu':'i586', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'transfig-3.2.8b-bp153.3.6.3', 'cpu':'s390x', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'transfig');
}
