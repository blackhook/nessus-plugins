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
  script_id(60231);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2007-2926");

  script_name(english:"Scientific Linux Security Update : bind on SL5.x, SL4.x, SL3.x i386/x86_64");
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
"A flaw was found in the way BIND generates outbound DNS query ids. If
an attacker is able to acquire a finite set of query IDs, it becomes
possible to accurately predict future query IDs. Future query ID
prediction may allow an attacker to conduct a DNS cache poisoning
attack, which can result in the DNS server returning incorrect client
query data. (CVE-2007-2926)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind0707&L=scientific-linux-errata&T=0&P=1166
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bab5ad38"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL3", reference:"bind-9.2.4-21.el3")) flag++;
if (rpm_check(release:"SL3", reference:"bind-chroot-9.2.4-21.el3")) flag++;
if (rpm_check(release:"SL3", reference:"bind-devel-9.2.4-21.el3")) flag++;
if (rpm_check(release:"SL3", reference:"bind-libs-9.2.4-21.el3")) flag++;
if (rpm_check(release:"SL3", reference:"bind-utils-9.2.4-21.el3")) flag++;

if (rpm_check(release:"SL4", reference:"bind-9.2.4-27.0.1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"bind-chroot-9.2.4-27.0.1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"bind-devel-9.2.4-27.0.1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"bind-libs-9.2.4-27.0.1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"bind-utils-9.2.4-27.0.1.el4")) flag++;

if (rpm_check(release:"SL5", reference:"bind-9.3.3-9.0.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"bind-chroot-9.3.3-9.0.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"bind-devel-9.3.3-9.0.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"bind-libbind-devel-9.3.3-9.0.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"bind-libs-9.3.3-9.0.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"bind-sdb-9.3.3-9.0.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"bind-utils-9.3.3-9.0.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"caching-nameserver-9.3.3-9.0.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
