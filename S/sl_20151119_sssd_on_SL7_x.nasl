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
  script_id(87575);
  script_version("2.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-5292");

  script_name(english:"Scientific Linux Security Update : sssd on SL7.x x86_64 (20151119)");
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
"It was found that SSSD's Privilege Attribute Certificate (PAC)
responder plug-in would leak a small amount of memory on each
authentication request. A remote attacker could potentially use this
flaw to exhaust all available memory on the system by making repeated
requests to a Kerberized daemon application configured to authenticate
using the PAC responder plug-in. (CVE-2015-5292)

The sssd packages have been upgraded to upstream version 1.13.0, which
provides a number of bug fixes and enhancements over the previous
version.

  - SSSD smart card support * Cache authentication in SSSD *
    SSSD supports overriding automatically discovered AD
    site * SSSD can now deny SSH access to locked accounts *
    SSSD enables UID and GID mapping on individual clients *
    Background refresh of cached entries * Multi-step
    prompting for one-time and long-term passwords * Caching
    for initgroups operations

Bugs fixed :

  - When the SELinux user content on an IdM server was set
    to an empty string, the SSSD SELinux evaluation utility
    returned an error.

  - If the ldap_child process failed to initialize
    credentials and exited with an error multiple times,
    operations that create files in some cases started
    failing due to an insufficient amount of i-nodes.

  - The SRV queries used a hard-coded TTL timeout, and
    environments that wanted the SRV queries to be valid for
    a certain time only were blocked. Now, SSSD parses the
    TTL value out of the DNS packet.

  - Previously, initgroups operation took an excessive
    amount of time. Now, logins and ID processing are faster
    for setups with AD back end and disabled ID mapping.

  - When an IdM client with Scientific Linux 7.1 or later
    was connecting to a server with Scientific Linux 7.0 or
    earlier, authentication with an AD trusted domain caused
    the sssd_be process to terminate unexpectedly.

  - If replication conflict entries appeared during HBAC
    processing, the user was denied access. Now, the
    replication conflict entries are skipped and users are
    permitted access.

  - The array of SIDs no longer contains an uninitialized
    value and SSSD no longer crashes.

  - SSSD supports GPOs from different domain controllers and
    no longer crashes when processing GPOs from different
    domain controllers.

  - SSSD could not refresh sudo rules that contained groups
    with special characters, such as parentheses, in their
    name.

  - The IPA names are not qualified on the client side if
    the server already qualified them, and IdM group members
    resolve even if default_domain_suffix is used on the
    server side.

  - The internal cache cleanup task has been disabled by
    default to improve performance of the sssd_be process.

  - Now, default_domain_suffix is not considered anymore for
    autofs maps.

  - The user can set subdomain_inherit=ignore_group-members
    to disable fetching group members for trusted domains.

  - The group resolution failed with an error message:
    'Error: 14 (Bad address)'. The binary GUID handling has
    been fixed.

Enhancements added :

  - The description of default_domain_suffix has been
    improved in the manual pages.

  - With the new '%0' template option, users on SSSD IdM
    clients can now use home directories set on AD."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1512&L=scientific-linux-errata&F=&S=&P=8032
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b620618f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libipa_hbac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libsss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libsss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libsss_nss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libsss_simpleifp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libsss_simpleifp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-sss-murmur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-sssdconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:sssd-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:sssd-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:sssd-common-pac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:sssd-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:sssd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:sssd-ipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:sssd-libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:sssd-libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/22");
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


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libipa_hbac-1.13.0-40.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libipa_hbac-devel-1.13.0-40.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libsss_idmap-1.13.0-40.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libsss_idmap-devel-1.13.0-40.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libsss_nss_idmap-1.13.0-40.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libsss_nss_idmap-devel-1.13.0-40.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libsss_simpleifp-1.13.0-40.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libsss_simpleifp-devel-1.13.0-40.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-libipa_hbac-1.13.0-40.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-libsss_nss_idmap-1.13.0-40.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-sss-1.13.0-40.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-sss-murmur-1.13.0-40.el7")) flag++;
if (rpm_check(release:"SL7", reference:"python-sssdconfig-1.13.0-40.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sssd-1.13.0-40.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sssd-ad-1.13.0-40.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sssd-client-1.13.0-40.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sssd-common-1.13.0-40.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sssd-common-pac-1.13.0-40.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sssd-dbus-1.13.0-40.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sssd-debuginfo-1.13.0-40.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sssd-ipa-1.13.0-40.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sssd-krb5-1.13.0-40.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sssd-krb5-common-1.13.0-40.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sssd-ldap-1.13.0-40.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sssd-libwbclient-1.13.0-40.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sssd-libwbclient-devel-1.13.0-40.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sssd-proxy-1.13.0-40.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sssd-tools-1.13.0-40.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libipa_hbac / libipa_hbac-devel / libsss_idmap / libsss_idmap-devel / etc");
}
