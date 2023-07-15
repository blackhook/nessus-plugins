#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-513.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(135454);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/16");

  script_cve_id("CVE-2019-10206", "CVE-2019-10217", "CVE-2019-14846", "CVE-2019-14856", "CVE-2019-14858", "CVE-2019-14864", "CVE-2019-14904", "CVE-2019-14905");

  script_name(english:"openSUSE Security Update : ansible (openSUSE-2020-513)");
  script_summary(english:"Check for the openSUSE-2020-513 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for ansible to version 2.9.6 fixes the following issues :

Security issues fixed :

  - CVE-2019-14904: Fixed a vulnerability in solaris_zone
    module via crafted solaris zone (boo#1157968).

  - CVE-2019-14905: Fixed an issue where malicious code
    could craft filename in nxos_file_copy module
    (boo#1157969).

  - CVE-2019-14864: Fixed Splunk and Sumologic callback
    plugins leak sensitive data in logs (boo#1154830).

  - CVE-2019-14846: Fixed secrets disclosure on logs due to
    display is hardcoded to DEBUG level (boo#1153452)

  - CVE-2019-14856: Fixed insufficient fix for
    CVE-2019-10206 (boo#1154232)

  - CVE-2019-14858: Fixed data in the sub parameter fields
    that will not be masked and will be displayed when run
    with increased verbosity (boo#1154231) 

  - CVE-2019-10206: ansible-playbook -k and ansible cli
    tools prompt passwords by expanding them from templates
    as they could contain special characters. Passwords
    should be wrapped to prevent templates trigger and
    exposing them. (boo#1142690)

  - CVE-2019-10217: Fields managing sensitive data should be
    set as such by no_log feature. Some of these fields in
    GCP modules are not set properly.
    service_account_contents() which is common class for all
    gcp modules is not setting no_log to True. Any sensitive
    data managed by that function would be leak as an output
    when running ansible playbooks. (boo#1144453)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137479"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144453"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153452"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154231"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157969"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected ansible packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14904");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ansible-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"ansible-2.9.6-lp151.2.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ansible-test-2.9.6-lp151.2.7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ansible / ansible-test");
}
