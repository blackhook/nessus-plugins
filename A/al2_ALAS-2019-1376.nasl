#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1376.
#

include("compat.inc");

if (description)
{
  script_id(132264);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/29");

  script_cve_id("CVE-2019-11757", "CVE-2019-11758", "CVE-2019-11759", "CVE-2019-11760", "CVE-2019-11761", "CVE-2019-11762", "CVE-2019-11763", "CVE-2019-11764", "CVE-2019-15903");
  script_xref(name:"ALAS", value:"2019-1376");

  script_name(english:"Amazon Linux 2 : thunderbird (ALAS-2019-1376)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several memory safety bugs were discovered in Mozilla Firefox and
Thunderbird. Memory corruption and arbitrary code execution are
possible with these vulnerabilities. These bugs can be exploited over
the network.(CVE-2019-11764)

A flaw was discovered in both Firefox and Thunderbird where 4 bytes of
a HMAC output could be written past the end of a buffer stored on the
memory stack. This could allow an attacker to execute arbitrary code
or lead to a crash. This flaw can be exploited over the
network.(CVE-2019-11759)

A flaw was found in Mozilla Firefox and Thunderbird where null bytes
were incorrectly parsed in HTML entities. This could lead to HTML
comments being treated as code which could lead to XSS in a web
application or HTML entities being masked from
filters.(CVE-2019-11763)

A vulnerability was found in Mozilla Firefox and Thunderbird.
Privileged JSONView objects that have been cloned into content can be
accessed using a form with a data URI. This flaw bypasses existing
defense-in-depth mechanisms and can be exploited over the
network.(CVE-2019-11761)

A flaw was discovered in Mozilla Firefox and Thunderbird where a
fixed-stack buffer overflow could occur during WebRTC signalling. The
vulnerability could lead to an exploitable crash or leak
data.(CVE-2019-11760)

A use-after-free flaw was found in Mozilla Firefox and Thunderbird.
When following a value's prototype chain, it was possible to retain a
reference to a locale, delete it, and subsequently reference it. An
attacker could use this flaw to execute code that was stored in the
referenced memory or crash the system.(CVE-2019-11757)

In libexpat before 2.2.8, crafted XML input could fool the parser into
changing from DTD parsing to document parsing too early; a consecutive
call to XML_GetCurrentLineNumber (or XML_GetCurrentColumnNumber) then
resulted in a heap-based buffer over-read.(CVE-2019-15903)

A flaw was found in Mozilla's firefox and thunderbird where if two
same-origin documents set document.domain differently to become
cross-origin, it was possible for them to call arbitrary DOM
methods/getters/setters on the now-cross-origin window. This could
cause an interaction between two different sites on two different
windows running under the same application.(CVE-2019-11762)

A flaw was found in the 360 Total Security code in Firefox and
Thunderbird. Memory corruption is possible in the accessibility engine
that could lead to an exploit to run arbitrary code. This
vulnerability could be exploited over a network connection and would
affect confidentiality and integrity of information as well as
availability of the system.(CVE-2019-11758)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1376.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update thunderbird' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11764");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:thunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"thunderbird-68.2.0-1.amzn2.0.1", allowmaj:TRUE)) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"thunderbird-debuginfo-68.2.0-1.amzn2.0.1", allowmaj:TRUE)) flag++;

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
