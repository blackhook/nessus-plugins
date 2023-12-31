#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-541.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(75064);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2013-2013");

  script_name(english:"openSUSE Security Update : python-keystoneclient (openSUSE-SU-2013:1090-1)");
  script_summary(english:"Check for the openSUSE-2013-541 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of python-keystoneclient fixes a security vulnerability.

  - Add CVE-2013-2013.patch: allow secure user password
    update (CVE-2013-2013, bnc#817415)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=817415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2013-06/msg00199.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python-keystoneclient packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-keystoneclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-keystoneclient-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"python-keystoneclient-0.2.1.3.gd37a3fb+git.1357543650.d37a3fb-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-keystoneclient-test-0.2.1.3.gd37a3fb+git.1357543650.d37a3fb-2.8.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-keystoneclient / python-keystoneclient-test");
}
