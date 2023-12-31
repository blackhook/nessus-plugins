#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2022 Jacques Vidrine and contributors
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

include("compat.inc");

if (description)
{
  script_id(118707);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/31");

  script_cve_id("CVE-2018-16839", "CVE-2018-16840", "CVE-2018-16842");

  script_name(english:"FreeBSD : curl -- multiple vulnerabilities (e0ab1773-07c1-46c6-9170-4c5e81c00927)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"curl security problems :

CVE-2018-16839: SASL password overflow via integer overflow

libcurl contains a buffer overrun in the SASL authentication code.

The internal function Curl_auth_create_plain_message fails to
correctly verify that the passed in lengths for name and password
aren't too long, then calculates a buffer size to allocate.

On systems with a 32 bit size_t, the math to calculate the buffer size
triggers an integer overflow when the user name length exceeds 2GB
(2^31 bytes). This integer overflow usually causes a very small buffer
to actually get allocated instead of the intended very huge one,
making the use of that buffer end up in a heap buffer overflow.

This bug is very similar to CVE-2017-14618.

It affects curl 7.33.0 to 7.61.1.

CVE-2018-16840: use-after-free in handle close

libcurl contains a heap use-after-free flaw in code related to closing
an easy handle.

When closing and cleaning up an 'easy' handle in the Curl_close()
function, the library code first frees a struct (without nulling the
pointer) and might then subsequently erroneously write to a struct
field within that already freed struct.

It affects curl 7.59.0 to 7.61.1.

CVE-2018-16842: warning message out-of-buffer read

curl contains a heap out of buffer read vulnerability.

The command line tool has a generic function for displaying warning
and informational messages to stderr for various situations. For
example if an unknown command line argument is used, or passed to it
in a 'config' file.

This display function formats the output to wrap at 80 columns. The
wrap logic is however flawed, so if a single word in the message is
itself longer than 80 bytes the buffer arithmetic calculates the
remainder wrong and will end up reading behind the end of the buffer.
This could lead to information disclosure or crash.

This vulnerability could lead to a security issue if used in this or
similar situations :

1. a server somewhere uses the curl command line to run something

2. if it fails, it shows stderr to the user

3. the server takes user input for parts of its command line input

4. user provides something overly long that triggers this crash

5. the stderr output may now contain user memory contents that wasn't
meant to be available

It affects curl 7.14.1 to 7.61.1."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://curl.haxx.se/docs/security.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://curl.haxx.se/docs/CVE-2018-16839.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://curl.haxx.se/docs/CVE-2018-16840.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://curl.haxx.se/docs/CVE-2018-16842.html"
  );
  # https://vuxml.freebsd.org/freebsd/e0ab1773-07c1-46c6-9170-4c5e81c00927.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?79d7317b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16840");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:curl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"curl>=7.14.1<7.60.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
