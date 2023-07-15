#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:0559-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158340);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/03");

  script_cve_id(
    "CVE-2022-0566",
    "CVE-2022-22753",
    "CVE-2022-22754",
    "CVE-2022-22756",
    "CVE-2022-22759",
    "CVE-2022-22760",
    "CVE-2022-22761",
    "CVE-2022-22763",
    "CVE-2022-22764"
  );
  script_xref(name:"IAVA", value:"2022-A-0079-S");
  script_xref(name:"IAVA", value:"2022-A-0088-S");

  script_name(english:"openSUSE 15 Security Update : MozillaThunderbird (openSUSE-SU-2022:0559-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:0559-1 advisory.

  - It may be possible for an attacker to craft an email message that causes Thunderbird to perform an out-of-
    bounds write of one byte when processing the message.  (CVE-2022-0566)

  - A Time-of-Check Time-of-Use bug existed in the Maintenance (Updater) Service that could be abused to grant
    Users write access to an arbitrary directory. This could have been used to escalate to SYSTEM access. This
    bug only affects Thunderbird on Windows. Other operating systems are unaffected.  (CVE-2022-22753)

  - If a user installed an extension of a particular type, the extension could have auto-updated itself and
    while doing so, bypass the prompt which grants the new version the new requested permissions.
    (CVE-2022-22754)

  - If a user was convinced to drag and drop an image to their desktop or other folder, the resulting object
    could have been changed into an executable script which would have run arbitrary code after the user
    clicked on it.  (CVE-2022-22756)

  - If a document created a sandboxed iframe without <code>allow-scripts</code>, and subsequently appended an
    element to the iframe's document that e.g. had a JavaScript event handler - the event handler would have
    run despite the iframe's sandbox.  (CVE-2022-22759)

  - When importing resources using Web Workers, error messages would distinguish the difference between
    <code>application/javascript</code> responses and non-script responses.  This could have been abused to
    learn information cross-origin.  (CVE-2022-22760)

  - Web-accessible extension pages (pages with a moz-extension:// scheme) were not correctly enforcing the
    frame-ancestors directive when it was used in the Web Extension's Content Security Policy.
    (CVE-2022-22761)

  - When a worker is shutdown, it was possible to cause script to run late in the lifecycle, at a point after
    where it should not be possible.  (CVE-2022-22763)

  - Mozilla developers and community members Paul Adenot and the Mozilla Fuzzing Team reported memory safety
    bugs present in Thunderbird 91.5. Some of these bugs showed evidence of memory corruption and we presume
    that with enough effort some of these could have been exploited to run arbitrary code.  (CVE-2022-22764)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195682");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196072");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GSM3MOVKIHQAE33NLCNX7MUULCOLEADF/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?007d5e7b");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0566");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22754");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22756");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22759");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22760");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22761");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22763");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22764");
  script_set_attribute(attribute:"solution", value:
"Update the affected MozillaThunderbird, MozillaThunderbird-translations-common and / or MozillaThunderbird-translations-
other packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22764");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-22759");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'MozillaThunderbird-91.6.1-8.54.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'MozillaThunderbird-translations-common-91.6.1-8.54.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'MozillaThunderbird-translations-other-91.6.1-8.54.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'MozillaThunderbird / MozillaThunderbird-translations-common / etc');
}
