#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(128239);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/24");

  script_cve_id("CVE-2018-5383");

  script_name(english:"Scientific Linux Security Update : linux-firmware on SL7.x x86_64 (20190806)");
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

  - kernel: Bluetooth implementations may not sufficiently
    validate elliptic curve parameters during Diffie-Hellman
    key exchange (CVE-2018-5383)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1908&L=SCIENTIFIC-LINUX-ERRATA&P=23685
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b963cd15"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL7", reference:"iwl100-firmware-39.31.5.1-72.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"iwl100-firmware-39.31.5.1-72.el7")) flag++;
if (rpm_check(release:"SL7", reference:"iwl1000-firmware-39.31.5.1-72.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"iwl1000-firmware-39.31.5.1-72.el7")) flag++;
if (rpm_check(release:"SL7", reference:"iwl105-firmware-18.168.6.1-72.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"iwl105-firmware-18.168.6.1-72.el7")) flag++;
if (rpm_check(release:"SL7", reference:"iwl135-firmware-18.168.6.1-72.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"iwl135-firmware-18.168.6.1-72.el7")) flag++;
if (rpm_check(release:"SL7", reference:"iwl2000-firmware-18.168.6.1-72.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"iwl2000-firmware-18.168.6.1-72.el7")) flag++;
if (rpm_check(release:"SL7", reference:"iwl2030-firmware-18.168.6.1-72.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"iwl2030-firmware-18.168.6.1-72.el7")) flag++;
if (rpm_check(release:"SL7", reference:"iwl3160-firmware-22.0.7.0-72.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"iwl3160-firmware-22.0.7.0-72.el7")) flag++;
if (rpm_check(release:"SL7", reference:"iwl3945-firmware-15.32.2.9-72.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"iwl3945-firmware-15.32.2.9-72.el7")) flag++;
if (rpm_check(release:"SL7", reference:"iwl4965-firmware-228.61.2.24-72.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"iwl4965-firmware-228.61.2.24-72.el7")) flag++;
if (rpm_check(release:"SL7", reference:"iwl5000-firmware-8.83.5.1_1-72.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"iwl5000-firmware-8.83.5.1_1-72.el7")) flag++;
if (rpm_check(release:"SL7", reference:"iwl5150-firmware-8.24.2.2-72.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"iwl5150-firmware-8.24.2.2-72.el7")) flag++;
if (rpm_check(release:"SL7", reference:"iwl6000-firmware-9.221.4.1-72.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"iwl6000-firmware-9.221.4.1-72.el7")) flag++;
if (rpm_check(release:"SL7", reference:"iwl6000g2a-firmware-17.168.5.3-72.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"iwl6000g2a-firmware-17.168.5.3-72.el7")) flag++;
if (rpm_check(release:"SL7", reference:"iwl6000g2b-firmware-17.168.5.2-72.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"iwl6000g2b-firmware-17.168.5.2-72.el7")) flag++;
if (rpm_check(release:"SL7", reference:"iwl6050-firmware-41.28.5.1-72.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"iwl6050-firmware-41.28.5.1-72.el7")) flag++;
if (rpm_check(release:"SL7", reference:"iwl7260-firmware-22.0.7.0-72.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"iwl7260-firmware-22.0.7.0-72.el7")) flag++;
if (rpm_check(release:"SL7", reference:"iwl7265-firmware-22.0.7.0-72.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"iwl7265-firmware-22.0.7.0-72.el7")) flag++;
if (rpm_check(release:"SL7", reference:"linux-firmware-20190429-72.gitddde598.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"linux-firmware-20190429-72.gitddde598.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "iwl100-firmware / iwl1000-firmware / iwl105-firmware / etc");
}
