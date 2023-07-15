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
  script_id(100403);
  script_version("3.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/30");

  script_cve_id("CVE-2017-7494");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/04/20");

  script_name(english:"Scientific Linux Security Update : samba on SL6.x, SL7.x i386/x86_64 (20170524) (SambaCry)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Scientific Linux host is missing one or more security
updates.");
  script_set_attribute(attribute:"description", value:
"Security Fix(es) :

  - A remote code execution flaw was found in Samba. A
    malicious authenticated samba client, having write
    access to the samba share, could use this flaw to
    execute arbitrary code as root. (CVE-2017-7494)");
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1705&L=scientific-linux-errata&F=&S=&P=7563
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?528384a6");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba is_known_pipename() Arbitrary Module Load');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-domainjoin-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-krb5-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-test-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-vfs-glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-winbind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Scientific Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"SL6", reference:"libsmbclient-3.6.23-43.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"libsmbclient-devel-3.6.23-43.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"samba-3.6.23-43.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"samba-client-3.6.23-43.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"samba-common-3.6.23-43.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"samba-debuginfo-3.6.23-43.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"samba-doc-3.6.23-43.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"samba-domainjoin-gui-3.6.23-43.el6_9")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"samba-glusterfs-3.6.23-43.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"samba-swat-3.6.23-43.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"samba-winbind-3.6.23-43.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"samba-winbind-clients-3.6.23-43.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"samba-winbind-devel-3.6.23-43.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"samba-winbind-krb5-locator-3.6.23-43.el6_9")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libsmbclient-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libsmbclient-devel-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libwbclient-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libwbclient-devel-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-client-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-client-libs-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", reference:"samba-common-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-common-libs-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-common-tools-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-dc-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-dc-libs-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-debuginfo-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-devel-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-krb5-printing-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-libs-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", reference:"samba-pidl-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-python-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-test-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-test-libs-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-vfs-glusterfs-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-winbind-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-winbind-clients-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-winbind-krb5-locator-4.4.4-14.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-winbind-modules-4.4.4-14.el7_3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsmbclient / libsmbclient-devel / libwbclient / libwbclient-devel / etc");
}
