#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:1068-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151853);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/21");

  script_cve_id(
    "CVE-2020-8293",
    "CVE-2020-8294",
    "CVE-2020-8295",
    "CVE-2021-32678",
    "CVE-2021-32679",
    "CVE-2021-32680",
    "CVE-2021-32688",
    "CVE-2021-32703",
    "CVE-2021-32705",
    "CVE-2021-32725",
    "CVE-2021-32726",
    "CVE-2021-32734",
    "CVE-2021-32741"
  );

  script_name(english:"openSUSE 15 Security Update : nextcloud (openSUSE-SU-2021:1068-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:1068-1 advisory.

  - A missing input validation in Nextcloud Server before 20.0.2, 19.0.5, 18.0.11 allows users to store
    unlimited data in workflow rules causing load and potential DDoS on later interactions and usage with
    those rules. (CVE-2020-8293)

  - A missing link validation in Nextcloud Server before 20.0.2, 19.0.5, 18.0.11 allows execution of a stored
    XSS attack using Internet Explorer when saving a 'javascript:' URL in markdown format. (CVE-2020-8294)

  - A wrong check in Nextcloud Server 19 and prior allowed to perform a denial of service attack when
    resetting the password for a user. (CVE-2020-8295)

  - Nextcloud Server is a Nextcloud package that handles data storage. In versions prior to 19.0.13, 20.0.11,
    and 21.0.3, ratelimits are not applied to OCS API responses. This affects any OCS API controller
    (`OCSController`) using the `@BruteForceProtection` annotation. Risk depends on the installed applications
    on the Nextcloud Server, but could range from bypassing authentication ratelimits or spamming other
    Nextcloud users. The vulnerability is patched in versions 19.0.13, 20.0.11, and 21.0.3. No workarounds
    aside from upgrading are known to exist. (CVE-2021-32678)

  - Nextcloud Server is a Nextcloud package that handles data storage. In versions prior to 19.0.13, 20.0.11,
    and 21.0.3, filenames where not escaped by default in controllers using `DownloadResponse`. When a user-
    supplied filename was passed unsanitized into a `DownloadResponse`, this could be used to trick users into
    downloading malicious files with a benign file extension. This would show in UI behaviours where Nextcloud
    applications would display a benign file extension (e.g. JPEG), but the file will actually be downloaded
    with an executable file extension. The vulnerability is patched in versions 19.0.13, 20.0.11, and 21.0.3.
    Administrators of Nextcloud instances do not have a workaround available, but developers of Nextcloud apps
    may manually escape the file name before passing it into `DownloadResponse`. (CVE-2021-32679)

  - Nextcloud Server is a Nextcloud package that handles data storage. In versions priot to 19.0.13, 20.0.11,
    and 21.0.3, Nextcloud Server audit logging functionality wasn't properly logging events for the unsetting
    of a share expiration date. This event is supposed to be logged. This issue is patched in versions
    19.0.13, 20.0.11, and 21.0.3. (CVE-2021-32680)

  - Nextcloud Server is a Nextcloud package that handles data storage. Nextcloud Server supports application
    specific tokens for authentication purposes. These tokens are supposed to be granted to a specific
    applications (e.g. DAV sync clients), and can also be configured by the user to not have any filesystem
    access. Due to a lacking permission check, the tokens were able to change their own permissions in
    versions prior to 19.0.13, 20.0.11, and 21.0.3. Thus fileystem limited tokens were able to grant
    themselves access to the filesystem. The issue is patched in versions 19.0.13, 20.0.11, and 21.0.3. There
    are no known workarounds aside from upgrading. (CVE-2021-32688)

  - Nextcloud Server is a Nextcloud package that handles data storage. In versions prior to 19.0.13, 20.011,
    and 21.0.3, there was a lack of ratelimiting on the shareinfo endpoint. This may have allowed an attacker
    to enumerate potentially valid share tokens. The issue was fixed in versions 19.0.13, 20.0.11, and 21.0.3.
    There are no known workarounds. (CVE-2021-32703)

  - Nextcloud Server is a Nextcloud package that handles data storage. In versions prior to 19.0.13, 20.011,
    and 21.0.3, there was a lack of ratelimiting on the public DAV endpoint. This may have allowed an attacker
    to enumerate potentially valid share tokens or credentials. The issue was fixed in versions 19.0.13,
    20.0.11, and 21.0.3. There are no known workarounds. (CVE-2021-32705)

  - Nextcloud Server is a Nextcloud package that handles data storage. In versions prior to 19.0.13, 20.011,
    and 21.0.3, default share permissions were not being respected for federated reshares of files and
    folders. The issue was fixed in versions 19.0.13, 20.0.11, and 21.0.3. There are no known workarounds.
    (CVE-2021-32725)

  - Nextcloud Server is a Nextcloud package that handles data storage. In versions prior to 19.0.13, 20.011,
    and 21.0.3, webauthn tokens were not deleted after a user has been deleted. If a victim reused an earlier
    used username, the previous user could gain access to their account. The issue was fixed in versions
    19.0.13, 20.0.11, and 21.0.3. There are no known workarounds. (CVE-2021-32726)

  - Nextcloud Server is a Nextcloud package that handles data storage. In versions prior to 19.0.13, 20.011,
    and 21.0.3, the Nextcloud Text application shipped with Nextcloud Server returned verbatim exception
    messages to the user. This could result in a full path disclosure on shared files. The issue was fixed in
    versions 19.0.13, 20.0.11, and 21.0.3. As a workaround, one may disable the Nextcloud Text application in
    Nextcloud Server app settings. (CVE-2021-32734)

  - Nextcloud Server is a Nextcloud package that handles data storage. In versions prior to 19.0.13, 20.011,
    and 21.0.3, there was a lack of ratelimiting on the public share link mount endpoint. This may have
    allowed an attacker to enumerate potentially valid share tokens. The issue was fixed in versions 19.0.13,
    20.0.11, and 21.0.3. There are no known workarounds. (CVE-2021-32741)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181445");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181803");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181804");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188247");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188248");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188249");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188250");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188251");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188252");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188253");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188254");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188255");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188256");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/XBA6BUWCG7GXG6XVXJPYJLSFVWJRSYU7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?47e87029");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-8293");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-8294");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-8295");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32678");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32679");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32680");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32688");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32703");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32705");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32725");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32726");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32734");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32741");
  script_set_attribute(attribute:"solution", value:
"Update the affected nextcloud and / or nextcloud-apache packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32726");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nextcloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nextcloud-apache");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
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
release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.2|SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.2 / 15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

pkgs = [
    {'reference':'nextcloud-20.0.11-bp153.2.3.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nextcloud-20.0.11-bp153.2.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nextcloud-apache-20.0.11-bp153.2.3.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nextcloud-apache-20.0.11-bp153.2.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nextcloud / nextcloud-apache');
}
