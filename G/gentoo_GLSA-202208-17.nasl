#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202208-17.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(164145);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/16");

  script_cve_id(
    "CVE-2021-32653",
    "CVE-2021-32654",
    "CVE-2021-32655",
    "CVE-2021-32656",
    "CVE-2021-32657",
    "CVE-2021-32678",
    "CVE-2021-32679",
    "CVE-2021-32680",
    "CVE-2021-32688",
    "CVE-2021-32703",
    "CVE-2021-32705",
    "CVE-2021-32725",
    "CVE-2021-32726",
    "CVE-2021-32734",
    "CVE-2021-32800",
    "CVE-2021-32801",
    "CVE-2021-32802",
    "CVE-2021-41177",
    "CVE-2021-41178",
    "CVE-2021-41239",
    "CVE-2021-41241",
    "CVE-2022-24741",
    "CVE-2022-24888",
    "CVE-2022-24889",
    "CVE-2022-29243"
  );

  script_name(english:"GLSA-202208-17 : Nextcloud: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202208-17 (Nextcloud: Multiple Vulnerabilities)

  - Nextcloud Server is a Nextcloud package that handles data storage. Nextcloud Server versions prior to
    19.0.11, 20.0.10, or 21.0.2 send user IDs to the lookup server even if the user has no fields set to
    published. The vulnerability is patched in versions 19.0.11, 20.0.10, and 21.0.2; no workarounds outside
    the updates are known to exist. (CVE-2021-32653)

  - Nextcloud Server is a Nextcloud package that handles data storage. In versions prior to 19.0.11, 20.0.10,
    and 21.0.2, an attacker is able to receive write/read privileges on any Federated File Share. Since public
    links can be added as federated file share, this can also be exploited on any public link. Users can
    upgrade to patched versions (19.0.11, 20.0.10 or 21.0.2) or, as a workaround, disable federated file
    sharing. (CVE-2021-32654)

  - Nextcloud Server is a Nextcloud package that handles data storage. In versions prior to 19.0.11, 20.0.10,
    and 21.0.2, an attacker is able to convert a Files Drop link to a federated share. This causes an issue on
    the UI side of the sharing user. When the sharing user opens the sharing panel and tries to remove the
    Create privileges of this unexpected share, Nextcloud server would silently grant the share read
    privileges. The vulnerability is patched in versions 19.0.11, 20.0.10 and 21.0.2. No workarounds are known
    to exist. (CVE-2021-32655)

  - Nextcloud Server is a Nextcloud package that handles data storage. A vulnerability in federated share
    exists in versions prior to 19.0.11, 20.0.10, and 21.0.2. An attacker can gain access to basic information
    about users of a server by accessing a public link that a legitimate server user added as a federated
    share. This happens because Nextcloud supports sharing registered users with other Nextcloud servers,
    which can be done automatically when selecting the Add server automatically once a federated share was
    created successfully setting. The vulnerability is patched in versions 19.0.11, 20.0.10, and 21.0.2 As a
    workaround, disable Add server automatically once a federated share was created successfully in the
    Nextcloud settings. (CVE-2021-32656)

  - Nextcloud Server is a Nextcloud package that handles data storage. In versions of Nextcloud Server prior
    to 10.0.11, 20.0.10, and 21.0.2, a malicious user may be able to break the user administration page. This
    would disallow administrators to administrate users on the Nextcloud instance. The vulnerability is fixed
    in versions 19.0.11, 20.0.10, and 21.0.2. As a workaround, administrators can use the OCC command line
    tool to administrate the Nextcloud users. (CVE-2021-32657)

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

  - Nextcloud is an open-source, self-hosted productivity platform. Prior to versions 20.0.13, 21.0.5, and
    22.2.0, Nextcloud Server did not implement a database backend for rate-limiting purposes. Any component of
    Nextcloud using rate-limits (as as `AnonRateThrottle` or `UserRateThrottle`) was thus not rate limited on
    instances not having a memory cache backend configured. In the case of a default installation, this would
    notably include the rate-limits on the two factor codes. It is recommended that the Nextcloud Server be
    upgraded to 20.0.13, 21.0.5, or 22.2.0. As a workaround, enable a memory cache backend in `config.php`.
    (CVE-2021-41177)

  - Nextcloud is an open-source, self-hosted productivity platform. Prior to versions 20.0.13, 21.0.5, and
    22.2.0, a file traversal vulnerability makes an attacker able to download arbitrary SVG images from the
    host system, including user provided files. This could also be leveraged into a XSS/phishing attack, an
    attacker could upload a malicious SVG file that mimics the Nextcloud login form and send a specially
    crafted link to victims. The XSS risk here is mitigated due to the fact that Nextcloud employs a strict
    Content-Security-Policy disallowing execution of arbitrary JavaScript. It is recommended that the
    Nextcloud Server be upgraded to 20.0.13, 21.0.5 or 22.2.0. There are no known workarounds aside from
    upgrading. (CVE-2021-41178)

  - Nextcloud server is a self hosted system designed to provide cloud style services. In affected versions
    the User Status API did not consider the user enumeration settings by the administrator. This allowed a
    user to enumerate other users on the instance, even when user listings where disabled. It is recommended
    that the Nextcloud Server is upgraded to 20.0.14, 21.0.6 or 22.2.1. There are no known workarounds.
    (CVE-2021-41239)

  - Nextcloud server is a self hosted system designed to provide cloud style services. The groupfolders
    application for Nextcloud allows sharing a folder with a group of people. In addition, it allows setting
    advanced permissions on subfolders, for example, a user could be granted access to the groupfolder but
    not specific subfolders. Due to a lacking permission check in affected versions, a user could still access
    these subfolders by copying the groupfolder to another location. It is recommended that the Nextcloud
    Server is upgraded to 20.0.14, 21.0.6 or 22.2.1. Users unable to upgrade should disable the groupfolders
    application in the admin settings. (CVE-2021-41241)

  - Nextcloud server is an open source, self hosted cloud style services platform. In affected versions an
    attacker can cause a denial of service by uploading specially crafted files which will cause the server to
    allocate too much memory / CPU. It is recommended that the Nextcloud Server is upgraded to 21.0.8 , 22.2.4
    or 23.0.1. Users unable to upgrade should disable preview generation with the `'enable_previews'` config
    flag. (CVE-2022-24741)

  - Nextcloud Server is the file server software for Nextcloud, a self-hosted productivity platform. Prior to
    versions 20.0.14.4, 21.0.8, 22.2.4, and 23.0.1, it is possible to create files and folders that have
    leading and trailing \n, \r, \t, and \v characters. The server rejects files and folders that have these
    characters in the middle of their names, so this might be an opportunity for injection. This issue is
    fixed in versions 20.0.14.4, 21.0.8, 22.2.4, and 23.0.1. There are currently no known workarounds.
    (CVE-2022-24888)

  - Nextcloud Server is the file server software for Nextcloud, a self-hosted productivity platform. Prior to
    versions 21.0.8, 22.2.4, and 23.0.1, it is possible to trick administrators into enabling recommended
    apps for the Nextcloud server that they do not need, thus expanding their attack surface unnecessarily.
    This issue is fixed in versions 21.0.8 , 22.2.4, and 23.0.1. (CVE-2022-24889)

  - Nextcloud Server is the file server software for Nextcloud, a self-hosted productivity platform. Prior to
    versions 22.2.7 and 23.0.4, missing input-size validation of new session names allows users to create app
    passwords with long names. These long names are then loaded into memory on usage, resulting in impacted
    performance. Versions 22.2.7 and 23.0.4 contain a fix for this issue. There are currently no known
    workarounds available. (CVE-2022-29243)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202208-17");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=797253");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=802096");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=812443");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=820368");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=834803");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=835073");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=848873");
  script_set_attribute(attribute:"solution", value:
"All Nextcloud users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-apps/nextcloud-23.0.4");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32802");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:nextcloud");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : "www-apps/nextcloud",
    'unaffected' : make_list("ge 23.0.4"),
    'vulnerable' : make_list("lt 23.0.4")
  }
];

foreach package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Nextcloud");
}
