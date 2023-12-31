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
  script_id(60857);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2010-3069");

  script_name(english:"Scientific Linux Security Update : samba on SL3.x, SL4.x, SL5.x i386/x86_64");
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
"NOTE: This errata went out 2010-09-15, but this email was not sent.

A missing array boundary checking flaw was found in the way Samba
parsed the binary representation of Windows security identifiers
(SIDs). A malicious client could send a specially crafted SMB request
to the Samba server, resulting in arbitrary code execution with the
privileges of the Samba server (smbd). (CVE-2010-3069)

For Scientific Linux 4, this update also fixes the following bug :

  - Previously, the restorecon utility was required during
    the installationof the samba-common package. As a
    result, attempting to update sambawithout this utility
    installed may have failed with the following error :

/var/tmp/rpm-tmp.[xxxxx]: line 7: restorecon: command not found

With this update, the utility is only used when it is already present
on the system, and the package is now always updated as expected.
(BZ#629602)

After installing this update, the smb service will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=629602"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1009&L=scientific-linux-errata&T=0&P=1505
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3abc76c5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
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
if (rpm_check(release:"SL3", reference:"samba-3.0.9-1.3E.18")) flag++;
if (rpm_check(release:"SL3", reference:"samba-client-3.0.9-1.3E.18")) flag++;
if (rpm_check(release:"SL3", reference:"samba-common-3.0.9-1.3E.18")) flag++;
if (rpm_check(release:"SL3", reference:"samba-swat-3.0.9-1.3E.18")) flag++;

if (rpm_check(release:"SL4", reference:"samba-3.0.33-0.19.el4_8.3")) flag++;
if (rpm_check(release:"SL4", reference:"samba-client-3.0.33-0.19.el4_8.3")) flag++;
if (rpm_check(release:"SL4", reference:"samba-common-3.0.33-0.19.el4_8.3")) flag++;
if (rpm_check(release:"SL4", reference:"samba-swat-3.0.33-0.19.el4_8.3")) flag++;

if (rpm_check(release:"SL5", reference:"libsmbclient-3.0.33-3.29.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"libsmbclient-devel-3.0.33-3.29.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"samba-3.0.33-3.29.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"samba-client-3.0.33-3.29.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"samba-common-3.0.33-3.29.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"samba-swat-3.0.33-3.29.el5_5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
