#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(111496);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/24");

  script_cve_id("CVE-2018-10897");

  script_name(english:"Scientific Linux Security Update : yum-utils on SL6.x (noarch) (20180730)");
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

  - yum-utils: reposync: improper path validation may lead
    to directory traversal (CVE-2018-10897)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1807&L=scientific-linux-errata&F=&S=&P=12557
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5fa40177"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:yum-NetworkManager-dispatcher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:yum-plugin-aliases");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:yum-plugin-auto-update-debug-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:yum-plugin-changelog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:yum-plugin-fastestmirror");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:yum-plugin-filter-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:yum-plugin-fs-snapshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:yum-plugin-keys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:yum-plugin-list-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:yum-plugin-local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:yum-plugin-merge-conf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:yum-plugin-ovl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:yum-plugin-post-transaction-actions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:yum-plugin-priorities");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:yum-plugin-protectbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:yum-plugin-ps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:yum-plugin-remove-with-leaves");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:yum-plugin-rpm-warm-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:yum-plugin-security");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:yum-plugin-show-leaves");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:yum-plugin-tmprepo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:yum-plugin-tsflags");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:yum-plugin-upgrade-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:yum-plugin-verify");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:yum-plugin-versionlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:yum-updateonboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:yum-utils");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/02");
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
if (rpm_check(release:"SL6", reference:"yum-NetworkManager-dispatcher-1.1.30-42.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"yum-plugin-aliases-1.1.30-42.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"yum-plugin-auto-update-debug-info-1.1.30-42.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"yum-plugin-changelog-1.1.30-42.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"yum-plugin-fastestmirror-1.1.30-42.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"yum-plugin-filter-data-1.1.30-42.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"yum-plugin-fs-snapshot-1.1.30-42.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"yum-plugin-keys-1.1.30-42.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"yum-plugin-list-data-1.1.30-42.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"yum-plugin-local-1.1.30-42.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"yum-plugin-merge-conf-1.1.30-42.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"yum-plugin-ovl-1.1.30-42.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"yum-plugin-post-transaction-actions-1.1.30-42.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"yum-plugin-priorities-1.1.30-42.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"yum-plugin-protectbase-1.1.30-42.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"yum-plugin-ps-1.1.30-42.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"yum-plugin-remove-with-leaves-1.1.30-42.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"yum-plugin-rpm-warm-cache-1.1.30-42.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"yum-plugin-security-1.1.30-42.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"yum-plugin-show-leaves-1.1.30-42.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"yum-plugin-tmprepo-1.1.30-42.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"yum-plugin-tsflags-1.1.30-42.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"yum-plugin-upgrade-helper-1.1.30-42.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"yum-plugin-verify-1.1.30-42.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"yum-plugin-versionlock-1.1.30-42.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"yum-updateonboot-1.1.30-42.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"yum-utils-1.1.30-42.el6_10")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "yum-NetworkManager-dispatcher / yum-plugin-aliases / etc");
}
