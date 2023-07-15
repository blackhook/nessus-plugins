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
  script_id(82253);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2010-5312", "CVE-2012-6662");

  script_name(english:"Scientific Linux Security Update : ipa on SL7.x x86_64 (20150305)");
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
"Two cross-site scripting (XSS) flaws were found in jQuery, which
impacted the Identity Management web administrative interface, and
could allow an authenticated user to inject arbitrary HTML or web
script into the interface. (CVE-2010-5312, CVE-2012-6662)

Note: The IdM version provided by this update no longer uses jQuery.

  - Added the 'ipa-cacert-manage' command, which renews the
    Certification Authority (CA) file.

  - Added the ID Views feature.

  - IdM now supports using one-time password (OTP)
    authentication and allows gradual migration from
    proprietary OTP solutions to the IdM OTP solution.

  - Added the 'ipa-backup' and 'ipa-restore' commands to
    allow manual backups.

  - Added a solution for regulating access permissions to
    specific sections of the IdM server.

This update also fixes several bugs, including :

  - Previously, when IdM servers were configured to require
    the Transport Layer Security protocol version 1.1
    (TLSv1.1) or later in the httpd server, the 'ipa'
    command-line utility failed. With this update, running
    'ipa' works as expected with TLSv1.1 or later.

In addition, this update adds multiple enhancements, including :

  - The 'ipa-getkeytab' utility can now optionally fetch
    existing keytabs from the KDC. Previously, retrieving an
    existing keytab was not supported, as the only option
    was to generate a new key.

  - You can now create and manage a '.' root zone on IdM
    servers. DNS queries sent to the IdM DNS server use this
    configured zone instead of the public zone.

  - The IdM server web UI has been updated and is now based
    on the Patternfly framework, offering better
    responsiveness.

  - A new user attribute now enables provisioning systems to
    add custom tags for user objects. The tags can be used
    for automember rules or for additional local
    interpretation.

  - This update adds a new DNS zone type to ensure that
    forward and master zones are better separated. As a
    result, the IdM DNS interface complies with the forward
    zone semantics in BIND.

  - This update adds a set of Apache modules that external
    applications can use to achieve tighter interaction with
    IdM beyond simple authentication.

  - IdM supports configuring automember rules for automated
    assignment of users or hosts in respective groups
    according to their characteristics, such as the
    'userClass' or 'departmentNumber' attributes.
    Previously, the rules could be applied only to new
    entries. This update allows applying the rules also to
    existing users or hosts.

  - The extdom plug-in translates Security Identifiers
    (SIDs) of Active Directory (AD) users and groups to
    names and POSIX IDs. With this update, extdom returns
    the full member list for groups and the full list of
    group memberships for a user, the GECOS field, the home
    directory, as well as the login shell of a user. Also,
    an optional list of key-value pairs contains the SID of
    the requested object if the SID is available."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1503&L=scientific-linux-errata&T=0&P=3129
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7bd018d5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-admintools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-admintools-4.1.0-18.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-client-4.1.0-18.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-debuginfo-4.1.0-18.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-python-4.1.0-18.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-server-4.1.0-18.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-server-trust-ad-4.1.0-18.sl7")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ipa-admintools / ipa-client / ipa-debuginfo / ipa-python / etc");
}
