#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(85201);
  script_version("2.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2002-0389", "CVE-2015-2775");

  script_name(english:"Scientific Linux Security Update : mailman on SL6.x i386/x86_64 (20150722)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that mailman did not sanitize the list name before
passing it to certain MTAs. A local attacker could use this flaw to
execute arbitrary code as the user running mailman. (CVE-2015-2775)

It was found that mailman stored private email messages in a world-
readable directory. A local user could use this flaw to read private
mailing list archives. (CVE-2002-0389)

This update also fixes the following bugs :

  - Previously, it was impossible to configure Mailman in a
    way that Domain- based Message Authentication, Reporting
    &amp; Conformance (DMARC) would recognize Sender
    alignment for Domain Key Identified Mail (DKIM)
    signatures. Consequently, Mailman list subscribers that
    belonged to a mail server with a 'reject' policy for
    DMARC, such as yahoo.com or AOL.com, were unable to
    receive Mailman forwarded messages from senders residing
    in any domain that provided DKIM signatures. With this
    update, domains with a 'reject' DMARC policy are
    recognized correctly, and Mailman list administrators
    are able to configure the way these messages are
    handled. As a result, after a proper configuration,
    subscribers now correctly receive Mailman forwarded
    messages in this scenario.

  - Mailman used a console encoding when generating a
    subject for a 'welcome email' when new mailing lists
    were created by the 'newlist' command. Consequently,
    when the console encoding did not match the encoding
    used by Mailman for that particular language, characters
    in the 'welcome email' could be displayed incorrectly.
    Mailman has been fixed to use the correct encoding, and
    characters in the 'welcome email' are now displayed
    properly.

  - The 'rmlist' command used a hard-coded path to list data
    based on the VAR_PREFIX configuration variable. As a
    consequence, when the list was created outside of
    VAR_PREFIX, it was impossible to remove it using the
    'rmlist' command. With this update, the 'rmlist' command
    uses the correct LIST_DATA_DIR value instead of
    VAR_PREFIX, and it is now possible to remove the list in
    described situation.

  - Due to an incompatibility between Python and Mailman in
    Scientific Linux 6, when moderators were approving a
    moderated message to a mailing list and checked the
    'Preserve messages for the site administrator' checkbox,
    Mailman failed to approve the message and returned an
    error. This incompatibility has been fixed, and Mailman
    now approves messages as expected in this scenario.

  - When Mailman was set to not archive a list but the
    archive was not set to private, attachments sent to that
    list were placed in a public archive. Consequently,
    users of Mailman web interface could list private
    attachments because httpd configuration of public
    archive directory allows listing all files in the
    archive directory. The httpd configuration of Mailman
    has been fixed to not allow listing of private archive
    directory, and users of Mailman web interface are no
    longer able to list private attachments."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1508&L=scientific-linux-errata&F=&S=&P=1781
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?76d7f76a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mailman and / or mailman-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mailman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mailman-debuginfo");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"mailman-2.1.12-25.el6")) flag++;
if (rpm_check(release:"SL6", reference:"mailman-debuginfo-2.1.12-25.el6")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mailman / mailman-debuginfo");
}
