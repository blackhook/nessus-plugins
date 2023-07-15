#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2020-1408.
#

include("compat.inc");

if (description)
{
  script_id(134899);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/29");

  script_cve_id("CVE-2020-6792", "CVE-2020-6793", "CVE-2020-6794", "CVE-2020-6795", "CVE-2020-6798", "CVE-2020-6800");
  script_xref(name:"ALAS", value:"2020-1408");

  script_name(english:"Amazon Linux 2 : thunderbird (ALAS-2020-1408)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"When deriving an identifier for an email message, uninitialized memory
was used in addition to the message contents. This vulnerability
affects Thunderbird < 68.5. (CVE-2020-6792)

When processing an email message with an ill-formed envelope,
Thunderbird could read data from a random memory location. This
vulnerability affects Thunderbird < 68.5. (CVE-2020-6793)

Mozilla developers and community members reported memory safety bugs
present in Firefox 72 and Firefox ESR 68.4. Some of these bugs showed
evidence of memory corruption and we presume that with enough effort
some of these could have been exploited to run arbitrary code. In
general, these flaws cannot be exploited through email in the
Thunderbird product because scripting is disabled when reading mail,
but are potentially risks in browser or browser-like contexts. This
vulnerability affects Thunderbird < 68.5, Firefox < 73, and Firefox <
ESR68.5. (CVE-2020-6800)

If a template tag was used in a select tag, the parser could be
confused and allow JavaScript parsing and execution when it should not
be allowed. A site that relied on the browser behaving correctly could
suffer a cross-site scripting vulnerability as a result. In general,
this flaw cannot be exploited through email in the Thunderbird product
because scripting is disabled when reading mail, but is potentially a
risk in browser or browser-like contexts. This vulnerability affects
Thunderbird < 68.5, Firefox < 73, and Firefox < ESR68.5.
(CVE-2020-6798)

If a user saved passwords before Thunderbird 60 and then later set a
master password, an unencrypted copy of these passwords is still
accessible. This is because the older stored password file was not
deleted when the data was copied to a new format starting in
Thunderbird 60. The new master password is added only on the new file.
This could allow the exposure of stored password data outside of user
expectations. This vulnerability affects Thunderbird < 68.5.
(CVE-2020-6794)

When processing a message that contains multiple S/MIME signatures, a
bug in the MIME processing code caused a NULL pointer dereference,
leading to an unexploitable crash. This vulnerability affects
Thunderbird < 68.5. (CVE-2020-6795)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2020-1408.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update thunderbird' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:thunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"thunderbird-68.5.0-1.amzn2.0.1", allowmaj:TRUE)) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"thunderbird-debuginfo-68.5.0-1.amzn2.0.1", allowmaj:TRUE)) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird / thunderbird-debuginfo");
}
