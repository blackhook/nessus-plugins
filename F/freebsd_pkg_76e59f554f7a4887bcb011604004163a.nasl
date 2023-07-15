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
  script_id(105216);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-8872", "CVE-2017-9047", "CVE-2017-9048", "CVE-2017-9049", "CVE-2017-9050");

  script_name(english:"FreeBSD : libxml2 -- Multiple Issues (76e59f55-4f7a-4887-bcb0-11604004163a)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libxml2 developers report :

The htmlParseTryOrFinish function in HTMLparser.c in libxml2 2.9.4
allows attackers to cause a denial of service (buffer over-read) or
information disclosure.

A buffer overflow was discovered in libxml2
20904-GITv2.9.4-16-g0741801. The function xmlSnprintfElementContent in
valid.c is supposed to recursively dump the element content definition
into a char buffer 'buf' of size 'size'. The variable len is assigned
strlen(buf). If the content->type is XML_ELEMENT_CONTENT_ELEMENT, then
(i) the content->prefix is appended to buf (if it actually fits)
whereupon (ii) content->name is written to the buffer. However, the
check for whether the content->name actually fits also uses 'len'
rather than the updated buffer length strlen(buf). This allows us to
write about 'size' many bytes beyond the allocated memory. This
vulnerability causes programs that use libxml2, such as PHP, to crash.

libxml2 20904-GITv2.9.4-16-g0741801 is vulnerable to a stack-based
buffer overflow. The function xmlSnprintfElementContent in valid.c is
supposed to recursively dump the element content definition into a
char buffer 'buf' of size 'size'. At the end of the routine, the
function may strcat two more characters without checking whether the
current strlen(buf) + 2 < size. This vulnerability causes programs
that use libxml2, such as PHP, to crash.

libxml2 20904-GITv2.9.4-16-g0741801 is vulnerable to a heap-based
buffer over-read in the xmlDictComputeFastKey function in dict.c. This
vulnerability causes programs that use libxml2, such as PHP, to crash.
This vulnerability exists because of an incomplete fix for libxml2 Bug
759398.

libxml2 20904-GITv2.9.4-16-g0741801 is vulnerable to a heap-based
buffer over-read in the xmlDictAddString function in dict.c. This
vulnerability causes programs that use libxml2, such as PHP, to crash.
This vulnerability exists because of an incomplete fix for
CVE-2016-1839."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.gnome.org/show_bug.cgi?id=775200"
  );
  # http://www.openwall.com/lists/oss-security/2017/05/15/1
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.openwall.com/lists/oss-security/2017/05/15/1"
  );
  # http://www.securityfocus.com/bid/98599
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.securityfocus.com/bid/98599"
  );
  # http://www.openwall.com/lists/oss-security/2017/05/15/1
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.openwall.com/lists/oss-security/2017/05/15/1"
  );
  # http://www.securityfocus.com/bid/98556
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.securityfocus.com/bid/98556"
  );
  # http://www.openwall.com/lists/oss-security/2017/05/15/1
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.openwall.com/lists/oss-security/2017/05/15/1"
  );
  # http://www.securityfocus.com/bid/98601
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.securityfocus.com/bid/98601"
  );
  # http://www.openwall.com/lists/oss-security/2017/05/15/1
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.openwall.com/lists/oss-security/2017/05/15/1"
  );
  # http://www.securityfocus.com/bid/98568
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.securityfocus.com/bid/98568"
  );
  # https://vuxml.freebsd.org/freebsd/76e59f55-4f7a-4887-bcb0-11604004163a.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fff120c8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libxml2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/14");
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

if (pkg_test(save_report:TRUE, pkg:"libxml2<=2.9.4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
