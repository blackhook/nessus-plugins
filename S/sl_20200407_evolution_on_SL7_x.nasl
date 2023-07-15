#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(135807);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/24");

  script_cve_id("CVE-2018-15587", "CVE-2019-3890");

  script_name(english:"Scientific Linux Security Update : evolution on SL7.x x86_64 (20200407)");
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
"* evolution: specially crafted email leading to OpenPGP signatures
being spoofed for arbitrary messages * evolution-ews: all certificate
errors ignored if error is ignored during initial account setup in
gnome-online-accounts"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind2004&L=SCIENTIFIC-LINUX-ERRATA&P=3337
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a8e153c1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:atk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:atk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:atk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution-bogofilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution-data-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution-data-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution-data-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution-data-server-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution-data-server-langpacks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution-data-server-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution-data-server-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution-ews");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution-ews-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution-ews-langpacks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution-help");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution-langpacks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution-pst");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution-spamassassin");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"atk-2.28.1-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"atk-debuginfo-2.28.1-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"atk-devel-2.28.1-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"evolution-3.28.5-8.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"evolution-bogofilter-3.28.5-8.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"evolution-data-server-3.28.5-4.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"evolution-data-server-debuginfo-3.28.5-4.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"evolution-data-server-devel-3.28.5-4.el7")) flag++;
if (rpm_check(release:"SL7", reference:"evolution-data-server-doc-3.28.5-4.el7")) flag++;
if (rpm_check(release:"SL7", reference:"evolution-data-server-langpacks-3.28.5-4.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"evolution-data-server-langpacks-3.28.5-4.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"evolution-data-server-perl-3.28.5-4.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"evolution-data-server-tests-3.28.5-4.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"evolution-debuginfo-3.28.5-8.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"evolution-devel-3.28.5-8.el7")) flag++;
if (rpm_check(release:"SL7", reference:"evolution-devel-docs-3.28.5-8.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"evolution-ews-3.28.5-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"evolution-ews-debuginfo-3.28.5-5.el7")) flag++;
if (rpm_check(release:"SL7", reference:"evolution-ews-langpacks-3.28.5-5.el7")) flag++;
if (rpm_check(release:"SL7", reference:"evolution-help-3.28.5-8.el7")) flag++;
if (rpm_check(release:"SL7", reference:"evolution-langpacks-3.28.5-8.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"evolution-pst-3.28.5-8.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"evolution-spamassassin-3.28.5-8.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "atk / atk-debuginfo / atk-devel / evolution / evolution-bogofilter / etc");
}
