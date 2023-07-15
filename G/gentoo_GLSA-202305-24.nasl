#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202305-24.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(176192);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/21");

  script_cve_id(
    "CVE-2021-41798",
    "CVE-2021-41799",
    "CVE-2021-41800",
    "CVE-2021-44854",
    "CVE-2021-44855",
    "CVE-2021-44856",
    "CVE-2021-44857",
    "CVE-2021-44858",
    "CVE-2021-45038",
    "CVE-2022-28202",
    "CVE-2022-28205",
    "CVE-2022-28206",
    "CVE-2022-28209",
    "CVE-2022-31090",
    "CVE-2022-31091",
    "CVE-2022-34911",
    "CVE-2022-34912",
    "CVE-2022-41765",
    "CVE-2022-41766",
    "CVE-2022-41767",
    "CVE-2022-47927"
  );

  script_name(english:"GLSA-202305-24 : MediaWiki: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202305-24 (MediaWiki: Multiple Vulnerabilities)

  - MediaWiki before 1.36.2 allows XSS. Month related MediaWiki messages are not escaped before being used on
    the Special:Search results page. (CVE-2021-41798)

  - MediaWiki before 1.36.2 allows a denial of service (resource consumption because of lengthy query
    processing time). ApiQueryBacklinks (action=query&list=backlinks) can cause a full table scan.
    (CVE-2021-41799)

  - MediaWiki before 1.36.2 allows a denial of service (resource consumption because of lengthy query
    processing time). Visiting Special:Contributions can sometimes result in a long running SQL query because
    PoolCounter protection is mishandled. (CVE-2021-41800)

  - An issue was discovered in MediaWiki before 1.35.5, 1.36.x before 1.36.3, and 1.37.x before 1.37.1. The
    REST API publicly caches results from private wikis. (CVE-2021-44854)

  - An issue was discovered in MediaWiki before 1.35.5, 1.36.x before 1.36.3, and 1.37.x before 1.37.1. There
    is Blind Stored XSS via a URL to the Upload Image feature. (CVE-2021-44855)

  - An issue was discovered in MediaWiki before 1.35.5, 1.36.x before 1.36.3, and 1.37.x before 1.37.1. A
    title blocked by AbuseFilter can be created via Special:ChangeContentModel due to the mishandling of the
    EditFilterMergedContent hook return value. (CVE-2021-44856)

  - An issue was discovered in MediaWiki before 1.35.5, 1.36.x before 1.36.3, and 1.37.x before 1.37.1. It is
    possible to use action=mcrundo followed by action=mcrrestore to replace the content of any arbitrary page
    (that the user doesn't have edit rights for). This applies to any public wiki, or a private wiki that has
    at least one page set in $wgWhitelistRead. (CVE-2021-44857)

  - An issue was discovered in MediaWiki before 1.35.5, 1.36.x before 1.36.3, and 1.37.x before 1.37.1. It is
    possible to use action=edit&undo= followed by action=mcrundo and action=mcrrestore to view private pages
    on a private wiki that has at least one page set in $wgWhitelistRead. (CVE-2021-44858)

  - An issue was discovered in MediaWiki before 1.35.5, 1.36.x before 1.36.3, and 1.37.x before 1.37.1. By
    using an action=rollback query, attackers can view private wiki contents. (CVE-2021-45038)

  - An XSS issue was discovered in MediaWiki before 1.35.6, 1.36.x before 1.36.4, and 1.37.x before 1.37.2.
    The widthheight, widthheightpage, and nbytes properties of messages are not escaped when used in galleries
    or Special:RevisionDelete. (CVE-2022-28202)

  - An issue was discovered in MediaWiki through 1.37.1. The CentralAuth extension mishandles a ttl issue for
    groups expiring in the future. (CVE-2022-28205)

  - An issue was discovered in MediaWiki through 1.37.1. ImportPlanValidator.php in the FileImporter extension
    mishandles the check for edit rights. (CVE-2022-28206)

  - An issue was discovered in Mediawiki through 1.37.1. The check for the override-antispoof permission in
    the AntiSpoof extension is incorrect. (CVE-2022-28209)

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

  - An issue was discovered in MediaWiki before 1.35.8, 1.36.x and 1.37.x before 1.37.5, and 1.38.x before
    1.38.3. HTMLUserTextField exposes the existence of hidden users. (CVE-2022-41765)

  - An issue was discovered in MediaWiki before 1.35.8, 1.36.x and 1.37.x before 1.37.5, and 1.38.x before
    1.38.3. When changes made by an IP address are reassigned to a user (using reassignEdits.php), the changes
    will still be attributed to the IP address on Special:Contributions when doing a range lookup.
    (CVE-2022-41767)

  - An issue was discovered in MediaWiki before 1.35.9, 1.36.x through 1.38.x before 1.38.5, and 1.39.x before
    1.39.1. When installing with a pre-existing data directory that has weak permissions, the SQLite files are
    created with file mode 0644, i.e., world readable to local users. These files include credentials data.
    (CVE-2022-47927)

  - Mediawiki reports: (T316304, CVE-2022-41767) SECURITY: reassignEdits doesn't update results             in
    an IP range check on Special:Contributions.. (T309894, CVE-2022-41765) SECURITY: HTMLUserTextField exposes
    existence             of hidden users.  (T307278, CVE-2022-41766) SECURITY: On action=rollback the message
    alreadyrolled can leak revision deleted user name. (CVE-2022-41766)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202305-24");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=815376");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=829302");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=836430");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=855965");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=873385");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=888041");
  script_set_attribute(attribute:"solution", value:
"All MediaWiki users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-apps/mediawiki-1.38.5");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-28209");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mediawiki");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'www-apps/mediawiki',
    'unaffected' : make_list("ge 1.38.5"),
    'vulnerable' : make_list("lt 1.38.5")
  }
];

foreach var package( packages ) {
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
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'MediaWiki');
}
