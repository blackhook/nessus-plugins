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
  script_id(104265);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-15189", "CVE-2017-15190", "CVE-2017-15191", "CVE-2017-15192", "CVE-2017-15193");

  script_name(english:"FreeBSD : wireshark -- multiple security issues (4684a426-774d-4390-aa19-b8dd481c4c94)");
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
"wireshark developers reports :

In Wireshark 2.4.0 to 2.4.1, the DOCSIS dissector could go into an
infinite loop. This was addressed in plugins/docsis/packet-docsis.c by
adding decrements.

In Wireshark 2.4.0 to 2.4.1, the RTSP dissector could crash. This was
addressed in epan/dissectors/packet-rtsp.c by correcting the scope of
a variable.

In Wireshark 2.4.0 to 2.4.1, 2.2.0 to 2.2.9, and 2.0.0 to 2.0.15, the
DMP dissector could crash. This was addressed in
epan/dissectors/packet-dmp.c by validating a string length.

In Wireshark 2.4.0 to 2.4.1 and 2.2.0 to 2.2.9, the BT ATT dissector
could crash. This was addressed in epan/dissectors/packet-btatt.c by
considering a case where not all of the BTATT packets have the same
encapsulation level.

In Wireshark 2.4.0 to 2.4.1 and 2.2.0 to 2.2.9, the MBIM dissector
could crash or exhaust system memory. This was addressed in
epan/dissectors/packet-mbim.c by changing the memory-allocation
approach."
  );
  # http://www.securityfocus.com/bid/101227
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.securityfocus.com/bid/101227"
  );
  # http://www.securityfocus.com/bid/101228
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.securityfocus.com/bid/101228"
  );
  # http://www.securityfocus.com/bid/101229
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.securityfocus.com/bid/101229"
  );
  # http://www.securityfocus.com/bid/101235
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.securityfocus.com/bid/101235"
  );
  # http://www.securityfocus.com/bid/101240
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.securityfocus.com/bid/101240"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=14049"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=14056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=14068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=14077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=14080"
  );
  # https://code.wireshark.org/review/23470
  script_set_attribute(
    attribute:"see_also",
    value:"https://code.wireshark.org/review/#/c/23470/"
  );
  # https://code.wireshark.org/review/23537
  script_set_attribute(
    attribute:"see_also",
    value:"https://code.wireshark.org/review/#/c/23537/"
  );
  # https://code.wireshark.org/review/23591
  script_set_attribute(
    attribute:"see_also",
    value:"https://code.wireshark.org/review/#/c/23591/"
  );
  # https://code.wireshark.org/review/23635
  script_set_attribute(
    attribute:"see_also",
    value:"https://code.wireshark.org/review/#/c/23635/"
  );
  # https://code.wireshark.org/review/23663
  script_set_attribute(
    attribute:"see_also",
    value:"https://code.wireshark.org/review/#/c/23663/"
  );
  # https://code.wireshark.org/review/gitweb?p=wireshark.git;a=commit;h=3689dc1db36037436b1616715f9a3f888fc9a0f6
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ab47b25f"
  );
  # https://code.wireshark.org/review/gitweb?p=wireshark.git;a=commit;h=625bab309d9dd21db2d8ae2aa3511810d32842a8
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9f7612e1"
  );
  # https://code.wireshark.org/review/gitweb?p=wireshark.git;a=commit;h=8dbb21dfde14221dab09b6b9c7719b9067c1f06e
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bc000309"
  );
  # https://code.wireshark.org/review/gitweb?p=wireshark.git;a=commit;h=afb9ff7982971aba6e42472de0db4c1bedfc641b
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6740cc16"
  );
  # https://code.wireshark.org/review/gitweb?p=wireshark.git;a=commit;h=e27870eaa6efa1c2dac08aa41a67fe9f0839e6e0
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64a8a1a0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/security/wnpa-sec-2017-42.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/security/wnpa-sec-2017-43.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/security/wnpa-sec-2017-44.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/security/wnpa-sec-2017-45.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/security/wnpa-sec-2017-46.html"
  );
  # https://vuxml.freebsd.org/freebsd/4684a426-774d-4390-aa19-b8dd481c4c94.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e77837ed"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:wireshark");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/31");
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

if (pkg_test(save_report:TRUE, pkg:"wireshark>=2.2.0<=2.2.9")) flag++;
if (pkg_test(save_report:TRUE, pkg:"wireshark>=2.4.0<=2.4.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
