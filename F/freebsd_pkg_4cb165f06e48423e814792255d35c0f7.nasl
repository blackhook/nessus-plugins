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
  script_id(99553);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-5461", "CVE-2017-5462");

  script_name(english:"FreeBSD : NSS -- multiple vulnerabilities (4cb165f0-6e48-423e-8147-92255d35c0f7)");
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
"Mozilla Foundation reports :

An out-of-bounds write during Base64 decoding operation in the Network
Security Services (NSS) library due to insufficient memory being
allocated to the buffer. This results in a potentially exploitable
crash. The NSS library has been updated to fix this issue to address
this issue and Firefox 53 has been updated with NSS version 3.29.5.

A flaw in DRBG number generation within the Network Security Services
(NSS) library where the internal state V does not correctly carry bits
over. The NSS library has been updated to fix this issue to address
this issue and Firefox 53 has been updated with NSS version 3.29.5."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://hg.mozilla.org/projects/nss/rev/99a86619eac9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://hg.mozilla.org/projects/nss/rev/e126381a3c29"
  );
  # https://vuxml.freebsd.org/freebsd/4cb165f0-6e48-423e-8147-92255d35c0f7.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?61eb378b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-c6-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-c7-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-f10-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:nss");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/21");
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

if (pkg_test(save_report:TRUE, pkg:"nss>=3.30<3.30.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"nss>=3.29<3.29.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"nss>=3.22<3.28.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"nss<3.21.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-f10-nss>=3.30<3.30.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-f10-nss>=3.29<3.29.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-f10-nss>=3.22<3.28.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-f10-nss<3.21.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-c6-nss>=3.30<3.30.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-c6-nss>=3.29<3.29.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-c6-nss>=3.22<3.28.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-c6-nss<3.21.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-c7-nss>=3.30<3.30.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-c7-nss>=3.29<3.29.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-c7-nss>=3.22<3.28.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-c7-nss<3.21.4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
