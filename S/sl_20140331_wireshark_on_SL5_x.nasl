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
  script_id(73285);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-6056", "CVE-2012-6060", "CVE-2012-6061", "CVE-2012-6062", "CVE-2013-3557", "CVE-2013-3559", "CVE-2013-4081", "CVE-2013-4083", "CVE-2013-4927", "CVE-2013-4931", "CVE-2013-4932", "CVE-2013-4933", "CVE-2013-4934", "CVE-2013-4935", "CVE-2013-5721", "CVE-2013-7112", "CVE-2014-2281", "CVE-2014-2299");

  script_name(english:"Scientific Linux Security Update : wireshark on SL5.x i386/x86_64 (20140331)");
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
"Multiple flaws were found in Wireshark. If Wireshark read a malformed
packet off a network or opened a malicious dump file, it could crash
or, possibly, execute arbitrary code as the user running Wireshark.
(CVE-2013-3559, CVE-2013-4083, CVE-2014-2281, CVE-2014-2299)

Several denial of service flaws were found in Wireshark. Wireshark
could crash or stop responding if it read a malformed packet off a
network, or opened a malicious dump file. (CVE-2012-5595,
CVE-2012-5598, CVE-2012-5599, CVE-2012-5600, CVE-2012-6056,
CVE-2012-6060, CVE-2012-6061, CVE-2012-6062, CVE-2013-3557,
CVE-2013-4081, CVE-2013-4927, CVE-2013-4931, CVE-2013-4932,
CVE-2013-4933, CVE-2013-4934, CVE-2013-4935, CVE-2013-5721,
CVE-2013-7112)

All running instances of Wireshark must be restarted for the update to
take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1403&L=scientific-linux-errata&T=0&P=2855
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7b4cabfc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected wireshark, wireshark-debuginfo and / or
wireshark-gnome packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Wireshark wiretap/mpeg.c Stack Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:wireshark-gnome");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 5.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"wireshark-1.0.15-6.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"wireshark-debuginfo-1.0.15-6.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"wireshark-gnome-1.0.15-6.el5_10")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark / wireshark-debuginfo / wireshark-gnome");
}
