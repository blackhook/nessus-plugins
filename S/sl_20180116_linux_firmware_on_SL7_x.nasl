#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(106123);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/15");

  script_cve_id("CVE-2017-5715");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"Scientific Linux Security Update : linux-firmware on SL7.x (noarch) (20180116) (Spectre)");
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
"This update supersedes the previous microcode update provided with the
CVE-2017-5715 (Spectre) CPU branch injection vulnerability mitigation.
Further testing has uncovered problems with the microcode provided
along with the Spectre mitigation that could lead to system
instabilities.

As a result, this microcode update reverts to the last known good
microcode version dated before 03 January 2018.

You should contact your hardware provider for the latest microcode
updates.

IMPORTANT: If you are using Intel Skylake-, Broadwell-, and
Haswell-based platforms, obtain and install updated microcode from
your hardware vendor immediately. The 'Spectre' mitigation requires
both an updated kernel and updated microcode from your hardware
vendor."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1801&L=scientific-linux-errata&F=&S=&P=6269
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?79195c27"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:iwl100-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:iwl1000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:iwl105-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:iwl135-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:iwl2000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:iwl2030-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:iwl3160-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:iwl3945-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:iwl4965-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:iwl5000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:iwl5150-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:iwl6000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:iwl6000g2a-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:iwl6000g2b-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:iwl6050-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:iwl7260-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:iwl7265-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:linux-firmware");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL7", reference:"iwl100-firmware-39.31.5.1-58.el7_4")) flag++;
if (rpm_check(release:"SL7", reference:"iwl1000-firmware-39.31.5.1-58.el7_4")) flag++;
if (rpm_check(release:"SL7", reference:"iwl105-firmware-18.168.6.1-58.el7_4")) flag++;
if (rpm_check(release:"SL7", reference:"iwl135-firmware-18.168.6.1-58.el7_4")) flag++;
if (rpm_check(release:"SL7", reference:"iwl2000-firmware-18.168.6.1-58.el7_4")) flag++;
if (rpm_check(release:"SL7", reference:"iwl2030-firmware-18.168.6.1-58.el7_4")) flag++;
if (rpm_check(release:"SL7", reference:"iwl3160-firmware-22.0.7.0-58.el7_4")) flag++;
if (rpm_check(release:"SL7", reference:"iwl3945-firmware-15.32.2.9-58.el7_4")) flag++;
if (rpm_check(release:"SL7", reference:"iwl4965-firmware-228.61.2.24-58.el7_4")) flag++;
if (rpm_check(release:"SL7", reference:"iwl5000-firmware-8.83.5.1_1-58.el7_4")) flag++;
if (rpm_check(release:"SL7", reference:"iwl5150-firmware-8.24.2.2-58.el7_4")) flag++;
if (rpm_check(release:"SL7", reference:"iwl6000-firmware-9.221.4.1-58.el7_4")) flag++;
if (rpm_check(release:"SL7", reference:"iwl6000g2a-firmware-17.168.5.3-58.el7_4")) flag++;
if (rpm_check(release:"SL7", reference:"iwl6000g2b-firmware-17.168.5.2-58.el7_4")) flag++;
if (rpm_check(release:"SL7", reference:"iwl6050-firmware-41.28.5.1-58.el7_4")) flag++;
if (rpm_check(release:"SL7", reference:"iwl7260-firmware-22.0.7.0-58.el7_4")) flag++;
if (rpm_check(release:"SL7", reference:"iwl7265-firmware-22.0.7.0-58.el7_4")) flag++;
if (rpm_check(release:"SL7", reference:"linux-firmware-20170606-58.gitc990aae.el7_4")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "iwl100-firmware / iwl1000-firmware / iwl105-firmware / etc");
}
