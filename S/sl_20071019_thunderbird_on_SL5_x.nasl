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
  script_id(60270);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2007-1095", "CVE-2007-2292", "CVE-2007-3511", "CVE-2007-3844", "CVE-2007-5334", "CVE-2007-5337", "CVE-2007-5338", "CVE-2007-5339", "CVE-2007-5340");

  script_name(english:"Scientific Linux Security Update : thunderbird on SL5.x, SL4.x, SL3.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several flaws were found in the way in which Thunderbird processed
certain malformed HTML mail content. An HTML mail message containing
malicious content could cause Thunderbird to crash or potentially
execute arbitrary code as the user running Thunderbird. JavaScript
support is disabled by default in Thunderbird; these issues are not
exploitable unless the user has enabled JavaScript. (CVE-2007-5338,
CVE-2007-5339, CVE-2007-5340)

Several flaws were found in the way in which Thunderbird displayed
malformed HTML mail content. An HTML mail message containing specially
crafted content could potentially trick a user into surrendering
sensitive information. (CVE-2007-1095, CVE-2007-3844, CVE-2007-3511,
CVE-2007-5334)

A flaw was found in the Thunderbird sftp protocol handler. A malicious
HTML mail message could access data from a remote sftp site, possibly
stealing sensitive user data. (CVE-2007-5337)

A request-splitting flaw was found in the way in which Thunderbird
generates a digest authentication request. If a user opened a
specially crafted URL, it was possible to perform cross-site scripting
attacks, web cache poisoning, or other, similar exploits.
(CVE-2007-2292)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind0710&L=scientific-linux-errata&T=0&P=1466
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?431a0734"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(16, 20, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/19");
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
if (rpm_check(release:"SL3", reference:"thunderbird-1.5.0.12-0.5.SL3")) flag++;

if (rpm_check(release:"SL4", reference:"thunderbird-1.5.0.12-0.5.el4")) flag++;

if (rpm_check(release:"SL5", reference:"thunderbird-1.5.0.12-5.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
