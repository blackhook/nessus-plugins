#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(45499);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-3555");

  script_name(english:"SuSE 10 Security Update : Mozilla NSS (ZYPP Patch Number 6977)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla NSS was updated to version 3.12.6.

This fixes all currently known issues in mozilla-nss, and also
implements the new TLS/SSL renegotiation handling. (CVE-2009-3555)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3555.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 6977.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:2, reference:"mozilla-nspr-4.8.2-1.5.2")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"mozilla-nspr-devel-4.8.2-1.5.2")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"mozilla-nss-3.12.6-3.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"mozilla-nss-devel-3.12.6-3.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"mozilla-nss-tools-3.12.6-3.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.8.2-1.5.2")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"mozilla-nss-32bit-3.12.6-3.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"mozilla-nspr-4.8.2-1.5.2")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"mozilla-nspr-devel-4.8.2-1.5.2")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"mozilla-nss-3.12.6-3.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"mozilla-nss-devel-3.12.6-3.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.8.2-1.5.2")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"mozilla-nss-32bit-3.12.6-3.4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
