#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-867.
#

include("compat.inc");

if (description)
{
  script_id(102181);
  script_version("3.4");
  script_cvs_date("Date: 2019/07/10 16:04:12");

  script_cve_id("CVE-2017-7890", "CVE-2017-9224", "CVE-2017-9226", "CVE-2017-9227", "CVE-2017-9228", "CVE-2017-9229");
  script_xref(name:"ALAS", value:"2017-867");

  script_name(english:"Amazon Linux AMI : php70 (ALAS-2017-867)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Out-of-bounds heap write in bitset_set_range() :

An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod
in Ruby through 2.4.1 and mbstring in PHP through 7.1.5. A heap
out-of-bounds write occurs in bitset_set_range() during regular
expression compilation due to an uninitialized variable from an
incorrect state transition. An incorrect state transition in
parse_char_class() could create an execution path that leaves a
critical local variable uninitialized until it's used as an index,
resulting in an out-of-bounds write memory corruption. (CVE-2017-9228)

Buffer over-read from unitialized data in gdImageCreateFromGifCtx
function

The GIF decoding function gdImageCreateFromGifCtx in gd_gif_in.c in
the GD Graphics Library (aka libgd), as used in PHP before 5.6.31 and
7.x before 7.1.7, does not zero colorMap arrays before use. A
specially crafted GIF image could use the uninitialized tables to read
~700 bytes from the top of the stack, potentially disclosing sensitive
information. (CVE-2017-7890)

Invalid pointer dereference in left_adjust_char_head() :

An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod
in Ruby through 2.4.1 and mbstring in PHP through 7.1.5. A SIGSEGV
occurs in left_adjust_char_head() during regular expression
compilation. Invalid handling of reg->dmax in forward_search_range()
could result in an invalid pointer dereference, normally as an
immediate denial-of-service condition. (CVE-2017-9229)

Heap buffer overflow in next_state_val() during regular expression
compilation :

An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod
in Ruby through 2.4.1 and mbstring in PHP through 7.1.5. A heap
out-of-bounds write or read occurs in next_state_val() during regular
expression compilation. Octal numbers larger than 0xff are not handled
correctly in fetch_token() and fetch_token_in_cc(). A malformed
regular expression containing an octal number in the form of \\700
would produce an invalid code point value larger than 0xff in
next_state_val(), resulting in an out-of-bounds write memory
corruption.(CVE-2017-9226)

Out-of-bounds stack read in mbc_enc_len() during regular expression
searching :

An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod
in Ruby through 2.4.1 and mbstring in PHP through 7.1.5. A stack
out-of-bounds read occurs in mbc_enc_len() during regular expression
searching. Invalid handling of reg->dmin in forward_search_range()
could result in an invalid pointer dereference, as an out-of-bounds
read from a stack buffer. (CVE-2017-9227)

Out-of-bounds stack read in match_at() during regular expression
searching :

An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod
in Ruby through 2.4.1 and mbstring in PHP through 7.1.5. A stack
out-of-bounds read occurs in match_at() during regular expression
searching. A logical error involving order of validation and access in
match_at() could result in an out-of-bounds read from a stack buffer.
(CVE-2017-9224)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-867.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update php70' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-pdo-dblib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-zip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"php70-7.0.21-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-bcmath-7.0.21-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-cli-7.0.21-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-common-7.0.21-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-dba-7.0.21-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-dbg-7.0.21-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-debuginfo-7.0.21-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-devel-7.0.21-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-embedded-7.0.21-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-enchant-7.0.21-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-fpm-7.0.21-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-gd-7.0.21-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-gmp-7.0.21-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-imap-7.0.21-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-intl-7.0.21-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-json-7.0.21-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-ldap-7.0.21-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-mbstring-7.0.21-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-mcrypt-7.0.21-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-mysqlnd-7.0.21-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-odbc-7.0.21-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-opcache-7.0.21-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-pdo-7.0.21-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-pdo-dblib-7.0.21-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-pgsql-7.0.21-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-process-7.0.21-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-pspell-7.0.21-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-recode-7.0.21-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-snmp-7.0.21-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-soap-7.0.21-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-tidy-7.0.21-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-xml-7.0.21-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-xmlrpc-7.0.21-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-zip-7.0.21-1.23.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php70 / php70-bcmath / php70-cli / php70-common / php70-dba / etc");
}
