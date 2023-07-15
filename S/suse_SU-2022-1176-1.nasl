#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:1176-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159738);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id(
    "CVE-2022-1097",
    "CVE-2022-1196",
    "CVE-2022-1197",
    "CVE-2022-24713",
    "CVE-2022-28281",
    "CVE-2022-28282",
    "CVE-2022-28285",
    "CVE-2022-28286",
    "CVE-2022-28289"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:1176-1");
  script_xref(name:"IAVA", value:"2022-A-0134-S");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : MozillaThunderbird (SUSE-SU-2022:1176-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2022:1176-1 advisory.

  - <code>NSSToken</code> objects were referenced via direct points, and could have been accessed in an unsafe
    way on different threads, leading to a use-after-free and potentially exploitable crash. This
    vulnerability affects Thunderbird < 91.8, Firefox < 99, and Firefox ESR < 91.8. (CVE-2022-1097)

  - After a VR Process is destroyed, a reference to it may have been retained and used, leading to a use-
    after-free and potentially exploitable crash. This vulnerability affects Thunderbird < 91.8 and Firefox
    ESR < 91.8. (CVE-2022-1196)

  - When importing a revoked key that specified key compromise as the revocation reason, Thunderbird did not
    update the existing copy of the key that was not yet revoked, and the existing key was kept as non-
    revoked. Revocation statements that used another revocation reason, or that didn't specify a revocation
    reason, were unaffected. This vulnerability affects Thunderbird < 91.8. (CVE-2022-1197)

  - regex is an implementation of regular expressions for the Rust language. The regex crate features built-in
    mitigations to prevent denial of service attacks caused by untrusted regexes, or untrusted input matched
    by trusted regexes. Those (tunable) mitigations already provide sane defaults to prevent attacks. This
    guarantee is documented and it's considered part of the crate's API. Unfortunately a bug was discovered in
    the mitigations designed to prevent untrusted regexes to take an arbitrary amount of time during parsing,
    and it's possible to craft regexes that bypass such mitigations. This makes it possible to perform denial
    of service attacks by sending specially crafted regexes to services accepting user-controlled, untrusted
    regexes. All versions of the regex crate before or equal to 1.5.4 are affected by this issue. The fix is
    include starting from regex 1.5.5. All users accepting user-controlled regexes are recommended to upgrade
    immediately to the latest version of the regex crate. Unfortunately there is no fixed set of problematic
    regexes, as there are practically infinite regexes that could be crafted to exploit this vulnerability.
    Because of this, it us not recommend to deny known problematic regexes. (CVE-2022-24713)

  - If a compromised content process sent an unexpected number of WebAuthN Extensions in a Register command to
    the parent process, an out of bounds write would have occurred leading to memory corruption and a
    potentially exploitable crash. This vulnerability affects Thunderbird < 91.8, Firefox < 99, and Firefox
    ESR < 91.8. (CVE-2022-28281)

  - By using a link with <code>rel=localization</code> a use-after-free could have been triggered by
    destroying an object during JavaScript execution and then referencing the object through a freed pointer,
    leading to a potential exploitable crash. This vulnerability affects Thunderbird < 91.8, Firefox < 99, and
    Firefox ESR < 91.8. (CVE-2022-28282)

  - When generating the assembly code for <code>MLoadTypedArrayElementHole</code>, an incorrect AliasSet was
    used. In conjunction with another vulnerability this could have been used for an out of bounds memory
    read. This vulnerability affects Thunderbird < 91.8, Firefox < 99, and Firefox ESR < 91.8.
    (CVE-2022-28285)

  - Due to a layout change, iframe contents could have been rendered outside of its border. This could have
    led to user confusion or spoofing attacks. This vulnerability affects Thunderbird < 91.8, Firefox < 99,
    and Firefox ESR < 91.8. (CVE-2022-28286)

  - Mozilla developers and community members Nika Layzell, Andrew McCreight, Gabriele Svelto, and the Mozilla
    Fuzzing Team reported memory safety bugs present in Thunderbird 91.7. Some of these bugs showed evidence
    of memory corruption and we presume that with enough effort some of these could have been exploited to run
    arbitrary code. This vulnerability affects Thunderbird < 91.8, Firefox < 99, and Firefox ESR < 91.8.
    (CVE-2022-28289)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197903");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-April/010699.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8fd955b8");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1097");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1196");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1197");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-24713");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-28281");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-28282");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-28285");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-28286");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-28289");
  script_set_attribute(attribute:"solution", value:
"Update the affected MozillaThunderbird, MozillaThunderbird-translations-common and / or MozillaThunderbird-translations-
other packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24713");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-28289");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15|SUSE15\.3)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(3|4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP3/4", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(3|4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3/4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'MozillaThunderbird-91.8.0-150200.8.65.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-91.8.0-150200.8.65.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-91.8.0-150200.8.65.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'sle-we-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-91.8.0-150200.8.65.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-91.8.0-150200.8.65.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-91.8.0-150200.8.65.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'sle-we-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-common-91.8.0-150200.8.65.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-common-91.8.0-150200.8.65.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-common-91.8.0-150200.8.65.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'sle-we-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-common-91.8.0-150200.8.65.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-common-91.8.0-150200.8.65.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-common-91.8.0-150200.8.65.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'sle-we-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-other-91.8.0-150200.8.65.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-other-91.8.0-150200.8.65.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-other-91.8.0-150200.8.65.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'sle-we-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-other-91.8.0-150200.8.65.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-other-91.8.0-150200.8.65.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-other-91.8.0-150200.8.65.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'sle-we-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-91.8.0-150200.8.65.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-91.8.0-150200.8.65.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-91.8.0-150200.8.65.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-91.8.0-150200.8.65.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-translations-common-91.8.0-150200.8.65.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-translations-common-91.8.0-150200.8.65.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-translations-common-91.8.0-150200.8.65.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-translations-common-91.8.0-150200.8.65.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-translations-other-91.8.0-150200.8.65.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-translations-other-91.8.0-150200.8.65.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-translations-other-91.8.0-150200.8.65.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-translations-other-91.8.0-150200.8.65.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-91.8.0-150200.8.65.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'MozillaThunderbird-translations-common-91.8.0-150200.8.65.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'MozillaThunderbird-translations-other-91.8.0-150200.8.65.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.3']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'MozillaThunderbird / MozillaThunderbird-translations-common / etc');
}
