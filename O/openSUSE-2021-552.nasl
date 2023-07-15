#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-552.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(148606);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/19");

  script_cve_id("CVE-2020-6816", "CVE-2020-6817", "CVE-2021-23980");

  script_name(english:"openSUSE Security Update : python-bleach (openSUSE-2021-552)");
  script_summary(english:"Check for the openSUSE-2021-552 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for python-bleach fixes the following issues :

  - CVE-2021-23980: Fixed mutation XSS on bleach.clean with
    specific combinations of allowed tags (boo#1184547)

Update to 3.1.5 :

  - replace missing ``setuptools`` dependency with
    ``packaging``. Thank you Benjamin Peterson.

Update to 3.1.4 (boo#1168280, CVE-2020-6817) :

  - ``bleach.clean`` behavior parsing style attributes could
    result in a regular expression denial of service
    (ReDoS). Calls to ``bleach.clean`` with an allowed tag
    with an allowed ``style`` attribute were vulnerable to
    ReDoS. For example, ``bleach.clean(..., attributes=('a':
    ['style']))``.

  - Style attributes with dashes, or single or double quoted
    values are cleaned instead of passed through.

update to 3.1.3 (boo#1167379, CVE-2020-6816) :

  - Add relative link to code of conduct. (#442)

  - Drop deprecated 'setup.py test' support. (#507)

  - Fix typo: curren -> current in tests/test_clean.py
    (#504)

  - Test on PyPy 7

  - Drop test support for end of life Python 3.4

  - ``bleach.clean`` behavior parsing embedded MathML and
    SVG content with RCDATA tags did not match browser
    behavior and could result in a mutation XSS. Calls to
    ``bleach.clean`` with ``strip=False`` and ``math`` or
    ``svg`` tags and one or more of the RCDATA tags
    ``script``, ``noscript``, ``style``, ``noframes``,
    ``iframe``, ``noembed``, or ``xmp`` in the allowed tags
    whitelist were vulnerable to a mutation XSS."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167379"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168280"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184547"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected python-bleach packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-bleach");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-bleach");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/15");
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

if ( rpm_check(release:"SUSE15.2", reference:"python2-bleach-3.1.5-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-bleach-3.1.5-lp152.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python2-bleach / python3-bleach");
}
