#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2018 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#    copyright notice, this list of conditions and the following
#    disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#    published online in any format, converted to PDF, PostScript,
#    RTF and other formats) must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
# 
# THIS DOCUMENTATION IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101332);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-9224", "CVE-2017-9226", "CVE-2017-9227", "CVE-2017-9228");

  script_name(english:"FreeBSD : oniguruma -- multiple vulnerabilities (b396cf6c-62e6-11e7-9def-b499baebfeaf)");
  script_summary(english:"Checks for updated packages in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote FreeBSD host is missing one or more security-related
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"the PHP project reports :

- A stack out-of-bounds read occurs in match_at() during regular
expression searching. A logical error involving order of validation
and access in match_at() could result in an out-of-bounds read from a
stack buffer (CVE-2017-9224).

- A heap out-of-bounds write or read occurs in next_state_val() during
regular expression compilation. Octal numbers larger than 0xff are not
handled correctly in fetch_token() and fetch_token_in_cc(). A
malformed regular expression containing an octal number in the form of
'\700' would produce an invalid code point value larger than 0xff in
next_state_val(), resulting in an out-of-bounds write memory
corruption (CVE-2017-9226).

- A stack out-of-bounds read occurs in mbc_enc_len() during regular
expression searching. Invalid handling of reg->dmin in
forward_search_range() could result in an invalid pointer dereference,
as an out-of-bounds read from a stack buffer (CVE-2017-9227).

- A heap out-of-bounds write occurs in bitset_set_range() during
regular expression compilation due to an uninitialized variable from
an incorrect state transition. An incorrect state transition in
parse_char_class() could create an execution path that leaves a
critical local variable uninitialized until it's used as an index,
resulting in an out-of-bounds write memory corruption (CVE-2017-9228).

- A SIGSEGV occurs in left_adjust_char_head() during regular
expression compilation. Invalid handling of reg->dmax in
forward_search_range() could result in an invalid pointer dereference,
normally as an immediate denial-of-service condition (CVE-2017-9228)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://php.net/ChangeLog-7.php"
  );
  # https://vuxml.freebsd.org/freebsd/b396cf6c-62e6-11e7-9def-b499baebfeaf.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d3123c8d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libevhtp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:oniguruma4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:oniguruma5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:oniguruma6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php70-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php71-mbstring");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"FreeBSD Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (pkg_test(save_report:TRUE, pkg:"libevhtp<1.2.14")) flag++;
if (pkg_test(save_report:TRUE, pkg:"oniguruma4<4.7.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"oniguruma5<5.9.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"oniguruma6<6.4.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56-mbstring<5.6.31")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php70-mbstring<7.0.21")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php71-mbstring<7.1.7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
