#%NASL_MIN_LEVEL 70300
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

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100441);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-5506", "CVE-2017-5507", "CVE-2017-5508", "CVE-2017-5509", "CVE-2017-5510", "CVE-2017-5511", "CVE-2017-6497", "CVE-2017-6498", "CVE-2017-6499", "CVE-2017-6500", "CVE-2017-6501", "CVE-2017-6502", "CVE-2017-7275", "CVE-2017-7606", "CVE-2017-7619", "CVE-2017-7941", "CVE-2017-7942", "CVE-2017-7943", "CVE-2017-8343", "CVE-2017-8344", "CVE-2017-8345", "CVE-2017-8346", "CVE-2017-8347", "CVE-2017-8348", "CVE-2017-8349", "CVE-2017-8350", "CVE-2017-8351", "CVE-2017-8352", "CVE-2017-8353", "CVE-2017-8354", "CVE-2017-8355", "CVE-2017-8356", "CVE-2017-8357", "CVE-2017-8765", "CVE-2017-8830", "CVE-2017-9141", "CVE-2017-9142", "CVE-2017-9143", "CVE-2017-9144");

  script_name(english:"FreeBSD : ImageMagick -- multiple vulnerabilities (50776801-4183-11e7-b291-b499baebfeaf)");
  script_summary(english:"Checks for updated packages in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote FreeBSD host is missing one or more security-related
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:"Please reference CVE/URL list for details"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://nvd.nist.gov/vuln/search/results?query=ImageMagick"
  );
  # https://vuxml.freebsd.org/freebsd/50776801-4183-11e7-b291-b499baebfeaf.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d111ba13"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ImageMagick-nox11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ImageMagick7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ImageMagick7-nox11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

if (pkg_test(save_report:TRUE, pkg:"ImageMagick<6.9.6.4_2,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ImageMagick>=6.9.7.0,1<6.9.8.8,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ImageMagick-nox11<6.9.6.4_2,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ImageMagick-nox11>=6.9.7.0,1<6.9.8.8,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ImageMagick7<7.0.5.9")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ImageMagick7-nox11<7.0.5.9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
