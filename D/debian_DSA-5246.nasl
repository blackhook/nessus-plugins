#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5246. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(165710);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/05");

  script_cve_id(
    "CVE-2021-44854",
    "CVE-2021-44855",
    "CVE-2021-44856",
    "CVE-2022-28201",
    "CVE-2022-28202",
    "CVE-2022-28203",
    "CVE-2022-29248",
    "CVE-2022-31042",
    "CVE-2022-31043",
    "CVE-2022-31090",
    "CVE-2022-31091",
    "CVE-2022-34911",
    "CVE-2022-34912",
    "CVE-2022-41765",
    "CVE-2022-41767"
  );

  script_name(english:"Debian DSA-5246-1 : mediawiki - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5246 advisory.

  - An issue was discovered in MediaWiki before 1.35.6, 1.36.x before 1.36.4, and 1.37.x before 1.37.2. Users
    with the editinterface permission can trigger infinite recursion, because a bare local interwiki is
    mishandled for the mainpage message. (CVE-2022-28201)

  - An XSS issue was discovered in MediaWiki before 1.35.6, 1.36.x before 1.36.4, and 1.37.x before 1.37.2.
    The widthheight, widthheightpage, and nbytes properties of messages are not escaped when used in galleries
    or Special:RevisionDelete. (CVE-2022-28202)

  - A denial-of-service issue was discovered in MediaWiki before 1.35.6, 1.36.x before 1.36.4, and 1.37.x
    before 1.37.2. When many files exist, requesting Special:NewFiles with actor as a condition can result in
    a very long running query. (CVE-2022-28203)

  - Guzzle is a PHP HTTP client. Guzzle prior to versions 6.5.6 and 7.4.3 contains a vulnerability with the
    cookie middleware. The vulnerability is that it is not checked if the cookie domain equals the domain of
    the server which sets the cookie via the Set-Cookie header, allowing a malicious server to set cookies for
    unrelated domains. The cookie middleware is disabled by default, so most library consumers will not be
    affected by this issue. Only those who manually add the cookie middleware to the handler stack or
    construct the client with ['cookies' => true] are affected. Moreover, those who do not use the same Guzzle
    client to call multiple domains and have disabled redirect forwarding are not affected by this
    vulnerability. Guzzle versions 6.5.6 and 7.4.3 contain a patch for this issue. As a workaround, turn off
    the cookie middleware. (CVE-2022-29248)

  - Guzzle is an open source PHP HTTP client. In affected versions the `Cookie` headers on requests are
    sensitive information. On making a request using the `https` scheme to a server which responds with a
    redirect to a URI with the `http` scheme, or on making a request to a server which responds with a
    redirect to a a URI to a different host, we should not forward the `Cookie` header on. Prior to this fix,
    only cookies that were managed by our cookie middleware would be safely removed, and any `Cookie` header
    manually added to the initial request would not be stripped. We now always strip it, and allow the cookie
    middleware to re-add any cookies that it deems should be there. Affected Guzzle 7 users should upgrade to
    Guzzle 7.4.4 as soon as possible. Affected users using any earlier series of Guzzle should upgrade to
    Guzzle 6.5.7 or 7.4.4. Users unable to upgrade may consider an alternative approach to use your own
    redirect middleware, rather than ours. If you do not require or expect redirects to be followed, one
    should simply disable redirects all together. (CVE-2022-31042)

  - Guzzle is an open source PHP HTTP client. In affected versions `Authorization` headers on requests are
    sensitive information. On making a request using the `https` scheme to a server which responds with a
    redirect to a URI with the `http` scheme, we should not forward the `Authorization` header on. This is
    much the same as to how we don't forward on the header if the host changes. Prior to this fix, `https` to
    `http` downgrades did not result in the `Authorization` header being removed, only changes to the host.
    Affected Guzzle 7 users should upgrade to Guzzle 7.4.4 as soon as possible. Affected users using any
    earlier series of Guzzle should upgrade to Guzzle 6.5.7 or 7.4.4. Users unable to upgrade may consider an
    alternative approach which would be to use their own redirect middleware. Alternately users may simply
    disable redirects all together if redirects are not expected or required. (CVE-2022-31043)

  - Guzzle, an extensible PHP HTTP client. `Authorization` headers on requests are sensitive information. In
    affected versions when using our Curl handler, it is possible to use the `CURLOPT_HTTPAUTH` option to
    specify an `Authorization` header. On making a request which responds with a redirect to a URI with a
    different origin (change in host, scheme or port), if we choose to follow it, we should remove the
    `CURLOPT_HTTPAUTH` option before continuing, stopping curl from appending the `Authorization` header to
    the new request. Affected Guzzle 7 users should upgrade to Guzzle 7.4.5 as soon as possible. Affected
    users using any earlier series of Guzzle should upgrade to Guzzle 6.5.8 or 7.4.5. Note that a partial fix
    was implemented in Guzzle 7.4.2, where a change in host would trigger removal of the curl-added
    Authorization header, however this earlier fix did not cover change in scheme or change in port. If you do
    not require or expect redirects to be followed, one should simply disable redirects all together.
    Alternatively, one can specify to use the Guzzle steam handler backend, rather than curl. (CVE-2022-31090)

  - Guzzle, an extensible PHP HTTP client. `Authorization` and `Cookie` headers on requests are sensitive
    information. In affected versions on making a request which responds with a redirect to a URI with a
    different port, if we choose to follow it, we should remove the `Authorization` and `Cookie` headers from
    the request, before containing. Previously, we would only consider a change in host or scheme. Affected
    Guzzle 7 users should upgrade to Guzzle 7.4.5 as soon as possible. Affected users using any earlier series
    of Guzzle should upgrade to Guzzle 6.5.8 or 7.4.5. Note that a partial fix was implemented in Guzzle
    7.4.2, where a change in host would trigger removal of the curl-added Authorization header, however this
    earlier fix did not cover change in scheme or change in port. An alternative approach would be to use your
    own redirect middleware, rather than ours, if you are unable to upgrade. If you do not require or expect
    redirects to be followed, one should simply disable redirects all together. (CVE-2022-31091)

  - An issue was discovered in MediaWiki before 1.35.7, 1.36.x and 1.37.x before 1.37.3, and 1.38.x before
    1.38.1. XSS can occur in configurations that allow a JavaScript payload in a username. After account
    creation, when it sets the page title to Welcome followed by the username, the username is not escaped:
    SpecialCreateAccount::successfulAction() calls ::showSuccessPage() with a message as second parameter, and
    OutputPage::setPageTitle() uses text(). (CVE-2022-34911)

  - An issue was discovered in MediaWiki before 1.37.3 and 1.38.x before 1.38.1. The contributions-title, used
    on Special:Contributions, is used as page title without escaping. Hence, in a non-default configuration
    where a username contains HTML entities, it won't be escaped. (CVE-2022-34912)

  - Mediawiki reports: (T292763. CVE-2021-44854) REST API incorrectly publicly caches             autocomplete
    search results from private wikis. (T271037, CVE-2021-44856) Title blocked in AbuseFilter can be created
    via             Special:ChangeContentModel. (T297322, CVE-2021-44857) Unauthorized users can use
    action=mcrundo to             replace the content of arbitrary pages.  (T297322, CVE-2021-44858)
    Unauthorized users can view contents of private             wikis using various actions. (T297574,
    CVE-2021-45038) Unauthorized users can access private wiki             contents using rollback action
    (T293589, CVE-2021-44855) Blind Stored XSS in VisualEditor media dialog. (T294686) Special:Nuke doesn't
    actually delete pages. (CVE-2021-44854, CVE-2021-44855, CVE-2021-44856)

  - Mediawiki reports: (T316304, CVE-2022-41767) SECURITY: reassignEdits doesn't update results             in
    an IP range check on Special:Contributions.. (T309894, CVE-2022-41765) SECURITY: HTMLUserTextField exposes
    existence             of hidden users.  (T307278, CVE-2022-41766) SECURITY: On action=rollback the message
    alreadyrolled can leak revision deleted user name. (CVE-2022-41765, CVE-2022-41767)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/mediawiki");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5246");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-44854");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-44855");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-44856");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-28201");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-28202");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-28203");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-29248");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-31042");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-31043");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-31090");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-31091");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-34911");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-34912");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41765");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41767");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/mediawiki");
  script_set_attribute(attribute:"solution", value:
"Upgrade the mediawiki packages.

For the stable distribution (bullseye), these problems have been fixed in version 1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29248");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mediawiki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mediawiki-classes");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'mediawiki', 'reference': '1:1.35.8-1~deb11u1'},
    {'release': '11.0', 'prefix': 'mediawiki-classes', 'reference': '1:1.35.8-1~deb11u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'mediawiki / mediawiki-classes');
}
