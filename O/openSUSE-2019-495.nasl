#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-495.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123204);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-0618");

  script_name(english:"openSUSE Security Update : mailman (openSUSE-2019-495)");
  script_summary(english:"Check for the openSUSE-2019-495 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for mailman to version 2.1.27 fixes the following issues :

This security issue was fixed :

  - CVE-2018-0618: Additional protections against injecting
    scripts into listinfo and error messages pages
    (bsc#1099510).

These non-security issues were fixed :

  - The hash generated when SUBSCRIBE_FORM_SECRET is set
    could have been the same as one generated at the same
    time for a different list and IP address.

  - An option has been added to bin/add_members to issue
    invitations instead of immediately adding members.

  - A new BLOCK_SPAMHAUS_LISTED_IP_SUBSCRIBE setting has
    been added to enable blocking web subscribes from IPv4
    addresses listed in Spamhaus SBL, CSS or XBL. It will
    work with IPv6 addresses if Python's py2-ipaddress
    module is installed. The module can be installed via pip
    if not included in your Python.

  - Mailman has a new 'security' log and logs authentication
    failures to the various web CGI functions. The logged
    data include the remote IP and can be used to automate
    blocking of IPs with something like fail2ban. Since
    Mailman 2.1.14, these have returned an http 401 status
    and the information should be logged by the web server,
    but this new log makes that more convenient. Also, the
    'mischief' log entries for 'hostile listname' noe
    include the remote IP if available.

  - admin notices of (un)subscribes now may give the source
    of the action. This consists of a %(whence)s replacement
    that has been added to the admin(un)subscribeack.txt
    templates. Thanks to Yasuhito FUTATSUKI for updating the
    non-English templates and help with internationalizing
    the reasons.

  - there is a new BLOCK_SPAMHAUS_LISTED_DBL_SUBSCRIBE
    setting to enable blocking web subscribes for addresses
    in domains listed in the Spamhaus DBL."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099510"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected mailman packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mailman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mailman-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mailman-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"mailman-2.1.27-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"mailman-debuginfo-2.1.27-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"mailman-debugsource-2.1.27-lp150.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mailman / mailman-debuginfo / mailman-debugsource");
}
