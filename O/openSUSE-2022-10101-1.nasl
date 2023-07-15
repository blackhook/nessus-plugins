#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:10101-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(164473);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/28");

  script_cve_id(
    "CVE-2020-15690",
    "CVE-2020-15692",
    "CVE-2020-15693",
    "CVE-2020-15694",
    "CVE-2021-21372",
    "CVE-2021-21373",
    "CVE-2021-21374",
    "CVE-2021-29495",
    "CVE-2021-41259"
  );

  script_name(english:"openSUSE 15 Security Update : nim (openSUSE-SU-2022:10101-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has a package installed that is affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:10101-1 advisory.

  - In Nim before 1.2.6, the standard library asyncftpclient lacks a check for whether a message contains a
    newline character. (CVE-2020-15690)

  - In Nim 1.2.4, the standard library browsers mishandles the URL argument to browsers.openDefaultBrowser.
    This argument can be a local file path that will be opened in the default explorer. An attacker can pass
    one argument to the underlying open command to execute arbitrary registered system commands.
    (CVE-2020-15692)

  - In Nim 1.2.4, the standard library httpClient is vulnerable to a CR-LF injection in the target URL. An
    injection is possible if the attacker controls any part of the URL provided in a call (such as
    httpClient.get or httpClient.post), the User-Agent header value, or custom HTTP header names or values.
    (CVE-2020-15693)

  - In Nim 1.2.4, the standard library httpClient fails to properly validate the server response. For example,
    httpClient.get().contentLength() does not raise any error if a malicious server provides a negative
    Content-Length. (CVE-2020-15694)

  - Nimble is a package manager for the Nim programming language. In Nim release version before versions
    1.2.10 and 1.4.4, Nimble doCmd is used in different places and can be leveraged to execute arbitrary
    commands. An attacker can craft a malicious entry in the packages.json package list to trigger code
    execution. (CVE-2021-21372)

  - Nimble is a package manager for the Nim programming language. In Nim release versions before versions
    1.2.10 and 1.4.4, nimble refresh fetches a list of Nimble packages over HTTPS by default. In case of
    error it falls back to a non-TLS URL http://irclogs.nim-lang.org/packages.json. An attacker able to
    perform MitM can deliver a modified package list containing malicious software packages. If the packages
    are installed and used the attack escalates to untrusted code execution. (CVE-2021-21373)

  - Nimble is a package manager for the Nim programming language. In Nim release versions before versions
    1.2.10 and 1.4.4, nimble refresh fetches a list of Nimble packages over HTTPS without full verification
    of the SSL/TLS certificate due to the default setting of httpClient. An attacker able to perform MitM can
    deliver a modified package list containing malicious software packages. If the packages are installed and
    used the attack escalates to untrusted code execution. (CVE-2021-21374)

  - Nim is a statically typed compiled systems programming language. In Nim standard library before 1.4.2,
    httpClient SSL/TLS certificate verification was disabled by default. Users can upgrade to version 1.4.2 to
    receive a patch or, as a workaround, set verifyMode = CVerifyPeer as documented. (CVE-2021-29495)

  - Nim is a systems programming language with a focus on efficiency, expressiveness, and elegance. In
    affected versions the uri.parseUri function which may be used to validate URIs accepts null bytes in the
    input URI. This behavior could be used to bypass URI validation. For example:
    parseUri(http://localhost\0hello).hostname is set to localhost\0hello. Additionally,
    httpclient.getContent accepts null bytes in the input URL and ignores any data after the first null byte.
    Example: getContent(http://localhost\0hello) makes a request to localhost:80. An attacker can use a null
    bytes to bypass the check and mount a SSRF attack. (CVE-2021-41259)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1175332");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1175333");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1175334");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181705");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185083");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185084");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185085");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185948");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192712");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/SNDISR45BBTIWW5MDTIQOSRHOEV3XUKF/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?842793f7");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-15690");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-15692");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-15693");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-15694");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21372");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21373");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21374");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29495");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-41259");
  script_set_attribute(attribute:"solution", value:
"Update the affected nim package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15692");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-41259");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nim");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.4");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.4)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.4', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'nim-1.6.6-bp154.2.3.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nim-1.6.6-bp154.2.3.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nim');
}
