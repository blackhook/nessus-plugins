#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2020 Jacques Vidrine and contributors
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
  script_id(134585);
  script_version("1.1");
  script_cvs_date("Date: 2020/03/16");

  script_name(english:"FreeBSD : zeek -- potential denial of service issues (4ae135f7-85cd-4c32-ad94-358271b31f7f)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jon Siwek of Corelight reports :

This release addresses the following security issues :

- Potential Denial of Service due to memory leak in DNS TSIG message
parsing. 

- Potential Denial of Service due to memory leak (or assertion when
compiling with assertions enabled) when receiving a second SSH KEX
message after a first. 

- Potential Denial of Service due to buffer read overflow and/or
memory leaks in Kerberos analyzer. The buffer read overflow could
occur when the Kerberos message indicates it contains an IPv6 address,
but does not send enough data to parse out a full IPv6 address. A
memory leak could occur when processing KRB_KDC_REQ KRB_KDC_REP
messages for message types that do not match a known/expected type. 

- Potential Denial of Service when sending many zero-length SSL/TLS
certificate data. Such messages underwent the full Zeek file analysis
treatment which is expensive (and meaninguless here) compared to how
cheaply one can 'create' or otherwise indicate many zero-length
contained in an SSL message. 

- Potential Denial of Service due to buffer read overflow in SMB
transaction data string handling. The length of strings being parsed
from SMB messages was trusted to be whatever the message claimed
instead of the actual length of data found in the message. 

- Potential Denial of Service due to NULL pointer dereference in FTP
ADAT Base64 decoding. 

- Potential Denial of Service due buffer read overflow in FTP analyzer
word/whitespace handling. This typically won't be a problem in most
default deployments of Zeek since the FTP analyzer receives data from
a ContentLine (NVT) support analyzer which first null-terminates the
buffer used for further FTP parsing."
  );
  # https://github.com/zeek/zeek/blob/9dda3602a760f00d9532c6314ea79108106033fa/NEWS
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?48b4ed58"
  );
  # https://vuxml.freebsd.org/freebsd/4ae135f7-85cd-4c32-ad94-358271b31f7f.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c0baddfc"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:zeek");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"zeek<3.0.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
