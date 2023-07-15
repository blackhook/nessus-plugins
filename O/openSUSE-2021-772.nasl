#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-772.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149881);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/27");

  script_cve_id("CVE-2020-11078", "CVE-2021-21240");

  script_name(english:"openSUSE Security Update : python-httplib2 (openSUSE-2021-772)");
  script_summary(english:"Check for the openSUSE-2021-772 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for python-httplib2 contains the following fixes :

Security fixes included in this update :

  - CVE-2021-21240: Fixed a regular expression denial of
    service via malicious header (bsc#1182053).

  - CVE-2020-11078: Fixed an issue where an attacker could
    change request headers and body (bsc#1171998).

Non security fixes included in this update :

  - Update in SLE to 0.19.0 (bsc#1182053, CVE-2021-21240)

  - update to 0.19.0 :

  - auth: parse headers using pyparsing instead of regexp

  - auth: WSSE token needs to be string not bytes

  - update to 0.18.1: (bsc#1171998, CVE-2020-11078)

  - explicit build-backend workaround for pip build
    isolation bug

  - IMPORTANT security vulnerability CWE-93 CRLF injection
    Force %xx quote of space, CR, LF characters in uri.

  - Ship test suite in source dist

  - Update to 0.17.1

  - python3: no_proxy was not checked with https

  - feature: Http().redirect_codes set, works after
    follow(_all)_redirects check This allows one line
    workaround for old gcloud library that uses 308 response
    without redirect semantics.

  - IMPORTANT cache invalidation change, fix 307 keep
    method, add 308 Redirects

  - proxy: username/password as str compatible with pysocks

  - python2: regression in connect() error handling

  - add support for password protected certificate files

  - feature: Http.close() to clean persistent connections
    and sensitive data

  - Update to 0.14.0 :

  - Python3: PROXY_TYPE_SOCKS5 with str user/pass raised
    TypeError

  - version update to 0.13.1 0.13.1

  - Python3: Use no_proxy
    https://github.com/httplib2/httplib2/pull/140 0.13.0

  - Allow setting TLS max/min versions
    https://github.com/httplib2/httplib2/pull/138 0.12.3

  - No changes to library. Distribute py3 wheels. 0.12.1

  - Catch socket timeouts and clear dead connection
    https://github.com/httplib2/httplib2/issues/18
    https://github.com/httplib2/httplib2/pull/111

  - Officially support Python 3.7 (package metadata)
    https://github.com/httplib2/httplib2/issues/123 0.12.0

  - Drop support for Python 3.3

  - ca_certs from environment HTTPLIB2_CA_CERTS or certifi
    https://github.com/httplib2/httplib2/pull/117

  - PROXY_TYPE_HTTP with non-empty user/pass raised
    TypeError: bytes required
    https://github.com/httplib2/httplib2/pull/115

  - Revert http:443->https workaround
    https://github.com/httplib2/httplib2/issues/112

  - eliminate connection pool read race
    https://github.com/httplib2/httplib2/pull/110

  - cache: stronger safename
    https://github.com/httplib2/httplib2/pull/101 0.11.3

  - No changes, just reupload of 0.11.2 after fixing
    automatic release conditions in Travis. 0.11.2

  - proxy: py3 NameError basestring
    https://github.com/httplib2/httplib2/pull/100 0.11.1

  - Fix HTTP(S)ConnectionWithTimeout AttributeError
    proxy_info https://github.com/httplib2/httplib2/pull/97
    0.11.0

  - Add DigiCert Global Root G2 serial
    033af1e6a711a9a0bb2864b11d09fae5
    https://github.com/httplib2/httplib2/pull/91

  - python3 proxy support
    https://github.com/httplib2/httplib2/pull/90

  - If no_proxy environment value ends with comma then proxy
    is not used
    https://github.com/httplib2/httplib2/issues/11

  - fix UnicodeDecodeError using socks5 proxy
    https://github.com/httplib2/httplib2/pull/64

  - Respect NO_PROXY env var in proxy_info_from_url
    https://github.com/httplib2/httplib2/pull/58

  - NO_PROXY=bar was matching foobar (suffix without dot
    delimiter) New behavior matches curl/wget :

  - no_proxy=foo.bar will only skip proxy for exact hostname
    match

  - no_proxy=.wild.card will skip proxy for
    any.subdomains.wild.card
    https://github.com/httplib2/httplib2/issues/94

  - Bugfix for Content-Encoding: deflate
    https://stackoverflow.com/a/22311297

  - deleted patches

  - Removing certifi patch: httplib2 started to use certifi
    and this is already bent to use system certificate
    bundle by another patch

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/httplib2/httplib2/issues/11"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/httplib2/httplib2/issues/112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/httplib2/httplib2/issues/123"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/httplib2/httplib2/issues/18"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/httplib2/httplib2/issues/94"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/httplib2/httplib2/pull/100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/httplib2/httplib2/pull/101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/httplib2/httplib2/pull/110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/httplib2/httplib2/pull/111"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/httplib2/httplib2/pull/115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/httplib2/httplib2/pull/117"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/httplib2/httplib2/pull/138"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/httplib2/httplib2/pull/140"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/httplib2/httplib2/pull/58"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/httplib2/httplib2/pull/64"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/httplib2/httplib2/pull/90"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/httplib2/httplib2/pull/91"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/httplib2/httplib2/pull/97"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://stackoverflow.com/a/22311297"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected python-httplib2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11078");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-httplib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-httplib2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"python2-httplib2-0.19.0-lp152.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-httplib2-0.19.0-lp152.6.3.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python2-httplib2 / python3-httplib2");
}
