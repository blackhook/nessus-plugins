#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(110892);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/24");

  script_cve_id("CVE-2017-12173");

  script_name(english:"Scientific Linux Security Update : sssd and ding-libs on SL6.x i386/x86_64 (20180619)");
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
"The ding-libs packages contain a set of libraries used by the System
Security Services Daemon (SSSD) as well as other projects, and provide
functions to manipulate file system path names (libpath_utils), a hash
table to manage storage and access time properties (libdhash), a data
type to collect data in a hierarchical structure (libcollection), a
dynamically growing, reference-counted array (libref_array), and a
library to process configuration files in initialization format (INI)
into a library collection data structure (libini_config).

Security Fix(es) :

  - sssd: unsanitized input when searching in local cache
    database (CVE-2017-12173)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1807&L=scientific-linux-errata&F=&S=&P=1083
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c6a8d923"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ding-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libbasicobjects");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libbasicobjects-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libcollection");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libcollection-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libdhash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libdhash-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libini_config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libini_config-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libipa_hbac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libpath_utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libpath_utils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libref_array");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libref_array-devel");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL6", reference:"ding-libs-debuginfo-0.4.0-13.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libbasicobjects-0.1.1-13.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libbasicobjects-devel-0.1.1-13.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libcollection-0.6.2-13.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libcollection-devel-0.6.2-13.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libdhash-0.4.3-13.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libdhash-devel-0.4.3-13.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libini_config-1.1.0-13.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libini_config-devel-1.1.0-13.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libipa_hbac-1.13.3-60.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libipa_hbac-devel-1.13.3-60.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libpath_utils-0.2.1-13.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libpath_utils-devel-0.2.1-13.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libref_array-0.1.4-13.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libref_array-devel-0.1.4-13.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libsss_idmap-1.13.3-60.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libsss_idmap-devel-1.13.3-60.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libsss_nss_idmap-1.13.3-60.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libsss_nss_idmap-devel-1.13.3-60.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libsss_simpleifp-1.13.3-60.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libsss_simpleifp-devel-1.13.3-60.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-libipa_hbac-1.13.3-60.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-libsss_nss_idmap-1.13.3-60.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-sss-1.13.3-60.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-sss-murmur-1.13.3-60.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-sssdconfig-1.13.3-60.el6")) flag++;
if (rpm_check(release:"SL6", reference:"sssd-1.13.3-60.el6")) flag++;
if (rpm_check(release:"SL6", reference:"sssd-ad-1.13.3-60.el6")) flag++;
if (rpm_check(release:"SL6", reference:"sssd-client-1.13.3-60.el6")) flag++;
if (rpm_check(release:"SL6", reference:"sssd-common-1.13.3-60.el6")) flag++;
if (rpm_check(release:"SL6", reference:"sssd-common-pac-1.13.3-60.el6")) flag++;
if (rpm_check(release:"SL6", reference:"sssd-dbus-1.13.3-60.el6")) flag++;
if (rpm_check(release:"SL6", reference:"sssd-debuginfo-1.13.3-60.el6")) flag++;
if (rpm_check(release:"SL6", reference:"sssd-ipa-1.13.3-60.el6")) flag++;
if (rpm_check(release:"SL6", reference:"sssd-krb5-1.13.3-60.el6")) flag++;
if (rpm_check(release:"SL6", reference:"sssd-krb5-common-1.13.3-60.el6")) flag++;
if (rpm_check(release:"SL6", reference:"sssd-ldap-1.13.3-60.el6")) flag++;
if (rpm_check(release:"SL6", reference:"sssd-proxy-1.13.3-60.el6")) flag++;
if (rpm_check(release:"SL6", reference:"sssd-tools-1.13.3-60.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ding-libs-debuginfo / libbasicobjects / libbasicobjects-devel / etc");
}
