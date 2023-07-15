#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2020:14421-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150683);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/10");

  script_cve_id(
    "CVE-2020-12402",
    "CVE-2020-12415",
    "CVE-2020-12416",
    "CVE-2020-12417",
    "CVE-2020-12418",
    "CVE-2020-12419",
    "CVE-2020-12420",
    "CVE-2020-12421",
    "CVE-2020-12422",
    "CVE-2020-12423",
    "CVE-2020-12424",
    "CVE-2020-12425",
    "CVE-2020-12426"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2020:14421-1");
  script_xref(name:"IAVA", value:"2020-A-0287-S");

  script_name(english:"SUSE SLES11 Security Update : MozillaFirefox (SUSE-SU-2020:14421-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2020:14421-1 advisory.

  - During RSA key generation, bignum implementations used a variation of the Binary Extended Euclidean
    Algorithm which entailed significantly input-dependent flow. This allowed an attacker able to perform
    electromagnetic-based side channel attacks to record traces leading to the recovery of the secret primes.
    *Note:* An unmodified Firefox browser does not generate RSA keys in normal operation and is not affected,
    but products built on top of it might. This vulnerability affects Firefox < 78. (CVE-2020-12402)

  - When %2F was present in a manifest URL, Firefox's AppCache behavior may have become confused and allowed
    a manifest to be served from a subdirectory. This could cause the appcache to be used to service requests
    for the top level directory. This vulnerability affects Firefox < 78. (CVE-2020-12415)

  - A VideoStreamEncoder may have been freed in a race condition with VideoBroadcaster::AddOrUpdateSink,
    resulting in a use-after-free, memory corruption, and a potentially exploitable crash. This vulnerability
    affects Firefox < 78. (CVE-2020-12416)

  - Due to confusion about ValueTags on JavaScript Objects, an object may pass through the type barrier,
    resulting in memory corruption and a potentially exploitable crash. *Note: this issue only affects Firefox
    on ARM64 platforms.* This vulnerability affects Firefox ESR < 68.10, Firefox < 78, and Thunderbird <
    68.10.0. (CVE-2020-12417)

  - Manipulating individual parts of a URL object could have caused an out-of-bounds read, leaking process
    memory to malicious JavaScript. This vulnerability affects Firefox ESR < 68.10, Firefox < 78, and
    Thunderbird < 68.10.0. (CVE-2020-12418)

  - When processing callbacks that occurred during window flushing in the parent process, the associated
    window may die; causing a use-after-free condition. This could have led to memory corruption and a
    potentially exploitable crash. This vulnerability affects Firefox ESR < 68.10, Firefox < 78, and
    Thunderbird < 68.10.0. (CVE-2020-12419)

  - When trying to connect to a STUN server, a race condition could have caused a use-after-free of a pointer,
    leading to memory corruption and a potentially exploitable crash. This vulnerability affects Firefox ESR <
    68.10, Firefox < 78, and Thunderbird < 68.10.0. (CVE-2020-12420)

  - When performing add-on updates, certificate chains terminating in non-built-in-roots were rejected (even
    if they were legitimately added by an administrator.) This could have caused add-ons to become out-of-date
    silently without notification to the user. This vulnerability affects Firefox ESR < 68.10, Firefox < 78,
    and Thunderbird < 68.10.0. (CVE-2020-12421)

  - In non-standard configurations, a JPEG image created by JavaScript could have caused an internal variable
    to overflow, resulting in an out of bounds write, memory corruption, and a potentially exploitable crash.
    This vulnerability affects Firefox < 78. (CVE-2020-12422)

  - When the Windows DLL webauthn.dll was missing from the Operating System, and a malicious one was placed
    in a folder in the user's %PATH%, Firefox may have loaded the DLL, leading to arbitrary code execution.
    *Note: This issue only affects the Windows operating system; other operating systems are unaffected.* This
    vulnerability affects Firefox < 78. (CVE-2020-12423)

  - When constructing a permission prompt for WebRTC, a URI was supplied from the content process. This URI
    was untrusted, and could have been the URI of an origin that was previously granted permission; bypassing
    the prompt. This vulnerability affects Firefox < 78. (CVE-2020-12424)

  - Due to confusion processing a hyphen character in Date.parse(), a one-byte out of bounds read could have
    occurred, leading to potential information disclosure. This vulnerability affects Firefox < 78.
    (CVE-2020-12425)

  - Mozilla developers and community members reported memory safety bugs present in Firefox 77. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Firefox < 78. (CVE-2020-12426)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1166238");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1167231");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1173576");
  # https://lists.suse.com/pipermail/sle-security-updates/2020-July/007099.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?36c43763");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-12402");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-12415");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-12416");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-12417");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-12418");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-12419");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-12420");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-12421");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-12422");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-12423");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-12424");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-12425");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-12426");
  script_set_attribute(attribute:"solution", value:
"Update the affected MozillaFirefox, MozillaFirefox-branding-SLED, MozillaFirefox-translations-common and / or
MozillaFirefox-translations-other packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12426");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-branding-SLED");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
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
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES11', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);

pkgs = [
    {'reference':'MozillaFirefox-78.0.1-78.80', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'MozillaFirefox-branding-SLED-78-21.12', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'MozillaFirefox-translations-common-78.0.1-78.80', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'MozillaFirefox-translations-other-78.0.1-78.80', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'MozillaFirefox-78.0.1-78.80', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'MozillaFirefox-branding-SLED-78-21.12', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'MozillaFirefox-translations-common-78.0.1-78.80', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'MozillaFirefox-translations-other-78.0.1-78.80', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  exists_check = NULL;
  rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release && exists_check) {
    if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
  else if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'MozillaFirefox / MozillaFirefox-branding-SLED / etc');
}
