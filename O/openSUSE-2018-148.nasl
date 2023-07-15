#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-148.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106703);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-15612", "CVE-2017-16876");

  script_name(english:"openSUSE Security Update : python-mistune (openSUSE-2018-148)");
  script_summary(english:"Check for the openSUSE-2018-148 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for python-mistune to version 0.8.3 fixes several issues.

These security issues were fixed :

  - CVE-2017-16876: Cross-site scripting (XSS) vulnerability
    in the _keyify function in mistune.py allowed remote
    attackers to inject arbitrary web script or HTML by
    leveraging failure to escape the 'key' argument
    (bsc#1072307).

  - CVE-2017-15612: Prevent XSS via an unexpected newline
    (such as in java\nscript:) or a crafted email address,
    related to the escape and autolink functions
    (bsc#1064640).

These non-security issues were fixed :

  - Fix nested html issue

  - Fix _keyify with lower case.

  - Remove non breaking spaces preprocessing

  - Remove rev and rel attribute for footnotes

  - Fix escape_link method 

  - Handle block HTML with no content 

  - Use expandtabs for tab

  - Fix escape option for text renderer

  - Fix HTML attribute regex pattern

  - Fix strikethrough regex

  - Fix HTML attribute regex

  - Fix close tag regex

  - Fix hard_wrap options on renderer.

  - Fix emphasis regex pattern

  - Fix base64 image link 

  - Fix link security per

  - Fix inline html when there is no content per"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064640"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1072307"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python-mistune packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-mistune");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-mistune");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE42.3", reference:"python-mistune-0.8.3-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python3-mistune-0.8.3-9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-mistune / python3-mistune");
}
