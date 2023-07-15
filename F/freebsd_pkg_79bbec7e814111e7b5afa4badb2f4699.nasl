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
  script_id(102491);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_name(english:"FreeBSD : FreeRadius -- Multiple vulnerabilities (79bbec7e-8141-11e7-b5af-a4badb2f4699)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Guido Vranken reports :

Multiple vulnerabilities found via fuzzing : FR-GV-201 (v2,v3) Read /
write overflow in make_secret() FR-GV-202 (v2) Write overflow in
rad_coalesce() FR-GV-203 (v2) DHCP - Memory leak in decode_tlv()
FR-GV-204 (v2) DHCP - Memory leak in fr_dhcp_decode() FR-GV-205 (v2)
DHCP - Buffer over-read in fr_dhcp_decode_options() FR-GV-206 (v2,v3)
DHCP - Read overflow when decoding option 63 FR-GV-207 (v2)
Zero-length malloc in data2vp() FR-GV-301 (v3) Write overflow in
data2vp_wimax() FR-GV-302 (v3) Infinite loop and memory exhaustion
with 'concat' attributes FR-GV-303 (v3) DHCP - Infinite read in
dhcp_attr2vp() FR-GV-304 (v3) DHCP - Buffer over-read in
fr_dhcp_decode_suboptions() FR-GV-305 (v3) Decode 'signed' attributes
correctly FR-AD-001 (v2,v3) Use strncmp() instead of memcmp() for
string data FR-AD-002 (v3) String lifetime issues in rlm_python
FR-AD-003 (v3) Incorrect statement length passed into sqlite3_prepare"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://freeradius.org/security/fuzzer-2017.html"
  );
  # https://vuxml.freebsd.org/freebsd/79bbec7e-8141-11e7-b5af-a4badb2f4699.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dbeb899d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:freeradius3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/15");
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

if (pkg_test(save_report:TRUE, pkg:"freeradius3<3.0.15")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
