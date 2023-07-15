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
  script_id(66462);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-2053");

  script_name(english:"Scientific Linux Security Update : openswan on SL5.x, SL6.x i386/x86_64 (20130515)");
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
"A buffer overflow flaw was found in Openswan. If Opportunistic
Encryption were enabled ('oe=yes' in '/etc/ipsec.conf') and an RSA key
configured, an attacker able to cause a system to perform a DNS lookup
for an attacker- controlled domain containing malicious records (such
as by sending an email that triggers a DKIM or SPF DNS record lookup)
could cause Openswan's pluto IKE daemon to crash or, potentially,
execute arbitrary code with root privileges. With 'oe=yes' but no RSA
key configured, the issue can only be triggered by attackers on the
local network who can control the reverse DNS entry of the target
system. Opportunistic Encryption is disabled by default.
(CVE-2013-2053)

After installing this update, the ipsec service will be restarted
automatically."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1305&L=scientific-linux-errata&T=0&P=1060
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b916a6c9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected openswan, openswan-debuginfo and / or openswan-doc
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openswan-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openswan-doc");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL5", reference:"openswan-2.6.32-5.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"openswan-debuginfo-2.6.32-5.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"openswan-doc-2.6.32-5.el5_9")) flag++;

if (rpm_check(release:"SL6", reference:"openswan-2.6.32-20.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"openswan-debuginfo-2.6.32-20.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"openswan-doc-2.6.32-20.el6_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openswan / openswan-debuginfo / openswan-doc");
}
