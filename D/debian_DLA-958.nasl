#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-958-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100478);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-9224", "CVE-2017-9226", "CVE-2017-9227", "CVE-2017-9228", "CVE-2017-9229");

  script_name(english:"Debian DLA-958-1 : libonig security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2017-9224

An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod
in Ruby through 2.4.1 and mbstring in PHP through 7.1.5. A stack
out-of-bounds read occurs in match_at() during regular expression
searching. A logical error involving order of validation and access in
match_at() could result in an out-of-bounds read from a stack buffer.

CVE-2017-9226

An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod
in Ruby through 2.4.1 and mbstring in PHP through 7.1.5. A heap
out-of-bounds write or read occurs in next_state_val() during regular
expression compilation. Octal numbers larger than 0xff are not handled
correctly in fetch_token() and fetch_token_in_cc(). A malformed
regular expression containing an octal number in the form of '\700'
would produce an invalid code point value larger than 0xff in
next_state_val(), resulting in an out-of-bounds write memory
corruption.

CVE-2017-9227

An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod
in Ruby through 2.4.1 and mbstring in PHP through 7.1.5. A stack
out-of-bounds read occurs in mbc_enc_len() during regular expression
searching. Invalid handling of reg-&gt;dmin in forward_search_range()
could result in an invalid pointer dereference, as an out-of-bounds
read from a stack buffer.

CVE-2017-9228

An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod
in Ruby through 2.4.1 and mbstring in PHP through 7.1.5. A heap
out-of-bounds write occurs in bitset_set_range() during regular
expression compilation due to an uninitialized variable from an
incorrect state transition. An incorrect state transition in
parse_char_class() could create an execution path that leaves a
critical local variable uninitialized until it's used as an index,
resulting in an out-of-bounds write memory corruption.

CVE-2017-9229

An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod
in Ruby through 2.4.1 and mbstring in PHP through 7.1.5. A SIGSEGV
occurs in left_adjust_char_head() during regular expression
compilation. Invalid handling of reg-&gt;dmax in
forward_search_range() could result in an invalid pointer dereference,
normally as an immediate denial of service condition.

For Debian 7 'Wheezy', these problems have been fixed in version
5.9.1-1+deb7u1.

We recommend that you upgrade your libonig packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/05/msg00029.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libonig"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected libonig-dev, libonig2, and libonig2-dbg packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libonig-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libonig2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libonig2-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"7.0", prefix:"libonig-dev", reference:"5.9.1-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libonig2", reference:"5.9.1-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libonig2-dbg", reference:"5.9.1-1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
