#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(119883);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/21");

  script_cve_id(
    "CVE-2018-15911",
    "CVE-2018-16541",
    "CVE-2018-16802",
    "CVE-2018-17183",
    "CVE-2018-17961",
    "CVE-2018-18073",
    "CVE-2018-18284",
    "CVE-2018-19134",
    "CVE-2018-19409"
  );
  script_xref(name:"IAVB", value:"2019-B-0081-S");

  script_name(english:"Scientific Linux Security Update : ghostscript on SL7.x x86_64 (20181217)");
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

  - ghostscript: Incorrect free logic in pagedevice
    replacement (699664) (CVE-2018-16541)

  - ghostscript: Incorrect 'restoration of privilege'
    checking when running out of stack during exception
    handling (CVE-2018-16802)

  - ghostscript: User-writable error exception table
    (CVE-2018-17183)

  - ghostscript: Saved execution stacks can leak operator
    arrays (incomplete fix for CVE-2018-17183)
    (CVE-2018-17961)

  - ghostscript: Saved execution stacks can leak operator
    arrays (CVE-2018-18073)

  - ghostscript: 1Policy operator allows a sandbox
    protection bypass (CVE-2018-18284)

  - ghostscript: Type confusion in setpattern (700141)
    (CVE-2018-19134)

  - ghostscript: Improperly implemented security check in
    zsetdevice function in psi/zdevice.c (CVE-2018-19409)

  - ghostscript: Uninitialized memory access in the
    aesdecode operator (699665) (CVE-2018-15911)

Bug Fix(es) :

  - It has been found that ghostscript-9.07-31.el7_6.1
    introduced regression during the handling of shading
    objects, causing a 'Dropping incorrect smooth shading
    object' warning. With this update, the regression has
    been fixed and the described problem no longer occurs."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1812&L=scientific-linux-errata&F=&S=&P=9988
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f8823a33");
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ghostscript-cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ghostscript-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ghostscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ghostscript-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ghostscript-gtk");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ghostscript-9.07-31.el7_6.6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ghostscript-cups-9.07-31.el7_6.6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ghostscript-debuginfo-9.07-31.el7_6.6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ghostscript-devel-9.07-31.el7_6.6")) flag++;
if (rpm_check(release:"SL7", reference:"ghostscript-doc-9.07-31.el7_6.6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ghostscript-gtk-9.07-31.el7_6.6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript / ghostscript-cups / ghostscript-debuginfo / etc");
}
