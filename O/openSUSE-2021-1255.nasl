#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:1255-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153393);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/15");

  script_cve_id(
    "CVE-2021-32766",
    "CVE-2021-32800",
    "CVE-2021-32801",
    "CVE-2021-32802"
  );

  script_name(english:"openSUSE 15 Security Update : nextcloud (openSUSE-SU-2021:1255-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:1255-1 advisory.

  - Nextcloud Text is an open source plaintext editing application which ships with the nextcloud server. In
    affected versions the Nextcloud Text application returned different error messages depending on whether a
    folder existed in a public link share. This is problematic in case the public link share has been created
    with Upload Only privileges. (aka File Drop). A link share recipient is not expected to see which
    folders or files exist in a File Drop share. Using this vulnerability an attacker is able to enumerate
    folders in such a share. Exploitation requires that the attacker has access to a valid affected File
    Drop link share. It is recommended that the Nextcloud Server is upgraded to 20.0.12, 21.0.4 or 22.0.1.
    Users who are unable to upgrade are advised to disable the Nextcloud Text application in the app settings.
    (CVE-2021-32766)

  - Nextcloud server is an open source, self hosted personal cloud. In affected versions an attacker is able
    to bypass Two Factor Authentication in Nextcloud. Thus knowledge of a password, or access to a WebAuthN
    trusted device of a user was sufficient to gain access to an account. It is recommended that the Nextcloud
    Server is upgraded to 20.0.12, 21.0.4 or 22.1.0. There are no workaround for this vulnerability.
    (CVE-2021-32800)

  - Nextcloud server is an open source, self hosted personal cloud. In affected versions logging of exceptions
    may have resulted in logging potentially sensitive key material for the Nextcloud Encryption-at-Rest
    functionality. It is recommended that the Nextcloud Server is upgraded to 20.0.12, 21.0.4 or 22.1.0. If
    upgrading is not an option users are advised to disable system logging to resolve this issue until such
    time that an upgrade can be performed Note that ff you do not use the Encryption-at-Rest functionality of
    Nextcloud you are not affected by this bug. (CVE-2021-32801)

  - Nextcloud server is an open source, self hosted personal cloud. Nextcloud supports rendering image
    previews for user provided file content. For some image types, the Nextcloud server was invoking a third-
    party library that wasn't suited for untrusted user-supplied content. There are several security concerns
    with passing user-generated content to this library, such as Server-Side-Request-Forgery, file disclosure
    or potentially executing code on the system. The risk depends on your system configuration and the
    installed library version. It is recommended that the Nextcloud Server is upgraded to 20.0.12, 21.0.4 or
    22.1.0. These versions do not use this library anymore. As a workaround users may disable previews by
    setting `enable_previews` to `false` in `config.php`. (CVE-2021-32802)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190291");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/FGLFYZROCOIJAG7C45FNC4EUIMNFJRIL/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4da5a9e1");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32766");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32800");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32801");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32802");
  script_set_attribute(attribute:"solution", value:
"Update the affected nextcloud and / or nextcloud-apache packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32802");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nextcloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nextcloud-apache");
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
    {'reference':'nextcloud-20.0.12-bp153.2.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nextcloud-apache-20.0.12-bp153.2.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nextcloud / nextcloud-apache');
}
