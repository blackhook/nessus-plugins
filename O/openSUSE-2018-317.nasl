#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-317.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(108640);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-2048", "CVE-2016-2512", "CVE-2016-2513", "CVE-2016-6186", "CVE-2016-7401", "CVE-2016-9013", "CVE-2016-9014", "CVE-2017-12794", "CVE-2017-7233", "CVE-2017-7234", "CVE-2018-7536", "CVE-2018-7537");

  script_name(english:"openSUSE Security Update : python-Django (openSUSE-2018-317)");
  script_summary(english:"Check for the openSUSE-2018-317 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for python-Django to version 1.18.18 fixes multiple
issues. Security issues fixed :

  - CVE-2018-7537: Fixed catastrophic backtracking in
    django.utils.text.Truncator. (bsc#1083305)

  - CVE-2018-7536: Fixed catastrophic backtracking in urlize
    and urlizetrunc template filters (bsc#1083304).

  - CVE-2016-7401: CSRF protection bypass on a site with
    Google Analytics (bsc#1001374).

  - CVE-2016-2513: User enumeration through timing
    difference on password hasher work factor upgrade
    (bsc#968000).

  - CVE-2016-2512: Fixed malicious redirect and possible XSS
    attack via user-supplied redirect URLs containing basic
    auth (bsc#967999).

  - CVE-2016-9013: User with hardcoded password created when
    running tests on Oracle (bsc#1008050).

  - CVE-2016-9014: DNS rebinding vulnerability when
    DEBUG=True (bsc#1008047).

  - CVE-2017-7234: Open redirect vulnerability in
    django.views.static.serve() (bsc#1031451).

  - CVE-2017-7233: Open redirect and possible XSS attack via
    user-supplied numeric redirect URLs (bsc#1031450).

  - CVE-2017-12794: Fixed XSS possibility in traceback
    section of technical 500 debug page (bsc#1056284)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1001374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1008047"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1008050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031450"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083305"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967999"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968000"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python-Django package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-Django");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"python-Django-1.8.19-6.4.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-Django");
}
