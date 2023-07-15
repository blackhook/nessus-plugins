#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2019 Jacques Vidrine and contributors
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
  script_id(107110);
  script_version("3.3");
  script_cvs_date("Date: 2019/03/12  9:14:55");

  script_cve_id("CVE-2017-14245", "CVE-2017-14246", "CVE-2017-17456", "CVE-2017-17457");

  script_name(english:"FreeBSD : libsndfile -- out-of-bounds reads (30704aba-1da4-11e8-b6aa-4ccc6adda413)");
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
"Xin-Jiang on Github reports :

CVE-2017-14245 (Medium): An out of bounds read in the function
d2alaw_array() in alaw.c of libsndfile 1.0.28 may lead to a remote DoS
attack or information disclosure, related to mishandling of the NAN
and INFINITY floating-point values.

CVE-2017-14246 (Medium): An out of bounds read in the function
d2ulaw_array() in ulaw.c of libsndfile 1.0.28 may lead to a remote DoS
attack or information disclosure, related to mishandling of the NAN
and INFINITY floating-point values.

my123px on Github reports :

CVE-2017-17456 (Medium): The function d2alaw_array() in alaw.c of
libsndfile 1.0.29pre1 may lead to a remote DoS attack (SEGV on unknown
address 0x000000000000), a different vulnerability than
CVE-2017-14245.

CVE-2017-17457 (Medium): The function d2ulaw_array() in ulaw.c of
libsndfile 1.0.29pre1 may lead to a remote DoS attack (SEGV on unknown
address 0x000000000000), a different vulnerability than
CVE-2017-14246."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/erikd/libsndfile/issues/317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/erikd/libsndfile/issues/344"
  );
  # https://vuxml.freebsd.org/freebsd/30704aba-1da4-11e8-b6aa-4ccc6adda413.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eafaddd6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libsndfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-c6-libsndfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-c7-libsndfile");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"libsndfile<1.0.28_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-c6-libsndfile<1.0.28_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-c7-libsndfile<1.0.28_2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
