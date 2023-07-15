#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(119200);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/01");

  script_cve_id("CVE-2018-10852");

  script_name(english:"Scientific Linux Security Update : sssd on SL7.x x86_64 (20181030)");
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
"Security Fix(es) :

  - sssd: information leak from the sssd-sudo responder
    (CVE-2018-10852)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1811&L=scientific-linux-errata&F=&S=&P=3470
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1a99e8d5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libipa_hbac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libsss_autofs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libsss_certmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libsss_certmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libsss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libsss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libsss_nss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libsss_simpleifp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libsss_simpleifp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libsss_sudo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:sssd-kcm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:sssd-libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:sssd-libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:sssd-polkit-rules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:sssd-winbind-idmap");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/27");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libipa_hbac-1.16.2-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libipa_hbac-devel-1.16.2-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libsss_autofs-1.16.2-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libsss_certmap-1.16.2-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libsss_certmap-devel-1.16.2-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libsss_idmap-1.16.2-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libsss_idmap-devel-1.16.2-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libsss_nss_idmap-1.16.2-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libsss_nss_idmap-devel-1.16.2-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libsss_simpleifp-1.16.2-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libsss_simpleifp-devel-1.16.2-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libsss_sudo-1.16.2-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-libipa_hbac-1.16.2-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-libsss_nss_idmap-1.16.2-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-sss-1.16.2-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-sss-murmur-1.16.2-13.el7")) flag++;
if (rpm_check(release:"SL7", reference:"python-sssdconfig-1.16.2-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sssd-1.16.2-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sssd-ad-1.16.2-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sssd-client-1.16.2-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sssd-common-1.16.2-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sssd-common-pac-1.16.2-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sssd-dbus-1.16.2-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sssd-debuginfo-1.16.2-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sssd-ipa-1.16.2-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sssd-kcm-1.16.2-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sssd-krb5-1.16.2-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sssd-krb5-common-1.16.2-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sssd-ldap-1.16.2-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sssd-libwbclient-1.16.2-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sssd-libwbclient-devel-1.16.2-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sssd-polkit-rules-1.16.2-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sssd-proxy-1.16.2-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sssd-tools-1.16.2-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sssd-winbind-idmap-1.16.2-13.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libipa_hbac / libipa_hbac-devel / libsss_autofs / libsss_certmap / etc");
}
