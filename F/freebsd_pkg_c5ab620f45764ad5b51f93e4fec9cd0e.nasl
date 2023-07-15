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
  script_id(107127);
  script_version("3.5");
  script_cvs_date("Date: 2019/07/10 16:04:13");

  script_cve_id("CVE-2018-7320", "CVE-2018-7321", "CVE-2018-7322", "CVE-2018-7323", "CVE-2018-7324", "CVE-2018-7325", "CVE-2018-7326", "CVE-2018-7327", "CVE-2018-7328", "CVE-2018-7329", "CVE-2018-7330", "CVE-2018-7331", "CVE-2018-7332", "CVE-2018-7333", "CVE-2018-7334", "CVE-2018-7335", "CVE-2018-7336", "CVE-2018-7337", "CVE-2018-7417");

  script_name(english:"FreeBSD : wireshark -- multiple security issues (c5ab620f-4576-4ad5-b51f-93e4fec9cd0e)");
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

wnpa-sec-2018-05. IEEE 802.11 dissector crash. (CVE-2018-7335)

wnpa-sec-2018-06. Large or infinite loops in multiple dissectors.
(CVE-2018-7321 through CVE-2018-7333)

wnpa-sec-2018-07. UMTS MAC dissector crash. (CVE-2018-7334)

wnpa-sec-2018-08. DOCSIS dissector crash. (CVE-2018-7337)

wnpa-sec-2018-09. FCP dissector crash. (CVE-2018-7336)

wnpa-sec-2018-10. SIGCOMP dissector crash. (CVE-2018-7320)

wnpa-sec-2018-11. Pcapng file parser crash.

wnpa-sec-2018-12. IPMI dissector crash.

wnpa-sec-2018-13. SIGCOMP dissector crash.

wnpa-sec-2018-14. NBAP dissector crash."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/security/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/security/wnpa-sec-2018-05.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/security/wnpa-sec-2018-06.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/security/wnpa-sec-2018-07.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/security/wnpa-sec-2018-08.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/security/wnpa-sec-2018-09.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/security/wnpa-sec-2018-10.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/security/wnpa-sec-2018-11.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/security/wnpa-sec-2018-12.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/security/wnpa-sec-2018-13.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/security/wnpa-sec-2018-14.html"
  );
  # https://vuxml.freebsd.org/freebsd/c5ab620f-4576-4ad5-b51f-93e4fec9cd0e.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?71e12b99"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:tshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:tshark-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:wireshark-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:wireshark-qt5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/05");
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

if (pkg_test(save_report:TRUE, pkg:"wireshark>=2.2.0<2.2.13")) flag++;
if (pkg_test(save_report:TRUE, pkg:"wireshark>=2.4.0<2.4.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"wireshark-lite>=2.2.0<2.2.13")) flag++;
if (pkg_test(save_report:TRUE, pkg:"wireshark-lite>=2.4.0<2.4.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"wireshark-qt5>=2.2.0<2.2.13")) flag++;
if (pkg_test(save_report:TRUE, pkg:"wireshark-qt5>=2.4.0<2.4.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tshark>=2.2.0<2.2.13")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tshark>=2.4.0<2.4.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tshark-lite>=2.2.0<2.2.13")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tshark-lite>=2.4.0<2.4.5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
