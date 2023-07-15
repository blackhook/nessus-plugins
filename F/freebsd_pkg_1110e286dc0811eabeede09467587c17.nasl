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
  script_id(139529);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/16");

  script_cve_id("CVE-2020-6542", "CVE-2020-6543", "CVE-2020-6544", "CVE-2020-6545", "CVE-2020-6546", "CVE-2020-6547", "CVE-2020-6548", "CVE-2020-6549", "CVE-2020-6550", "CVE-2020-6551", "CVE-2020-6552", "CVE-2020-6553", "CVE-2020-6554", "CVE-2020-6555");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (1110e286-dc08-11ea-beed-e09467587c17)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Chrome Releases reports :

This release contains 15 security fixes, including :

- [1107433] High CVE-2020-6542: Use after free in ANGLE. Reported by
Piotr Bania of Cisco Talos on 2020-07-20

- [1104046] High CVE-2020-6543: Use after free in task scheduling.
Reported by Looben Yang on 2020-07-10

- [1108497] High CVE-2020-6544: Use after free in media. Reported by
Tim Becker of Theori on 2020-07-22

- [1095584] High CVE-2020-6545: Use after free in audio. Reported by
Anonymous on 2020-06-16

- [1100280] High CVE-2020-6546: Inappropriate implementation in
installer. Reported by Andrew Hess (any1) on 2020-06-29

- [1102153] High CVE-2020-6547: Incorrect security UI in media.
Reported by David Albert on 2020-07-05

- [1103827] High CVE-2020-6548: Heap buffer overflow in Skia. Reported
by Choongwoo Han, Microsoft Browser Vulnerability Research on
2020-07-09

- [1105426] High CVE-2020-6549: Use after free in media. Reported by
Sergei Glazunov of Google Project Zero on 2020-07-14

- [1106682] High CVE-2020-6550: Use after free in IndexedDB. Reported
by Sergei Glazunov of Google Project Zero on 2020-07-17

- [1107815] High CVE-2020-6551: Use after free in WebXR. Reported by
Sergei Glazunov of Google Project Zero on 2020-07-21

- [1108518] High CVE-2020-6552: Use after free in Blink. Reported by
Tim Becker of Theori on 2020-07-22

- [1111307] High CVE-2020-6553: Use after free in offline mode.
Reported by Alison Huffman, Microsoft Browser Vulnerability Research
on 2020-07-30

- [1094235] Medium CVE-2020-6554: Use after free in extensions.
Reported by Anonymous on 2020-06-12

- [1105202] Medium CVE-2020-6555: Out of bounds read in WebGL.
Reported by Marcin Towalski of Cisco Talos on 2020-07-13"
  );
  # https://chromereleases.googleblog.com/2020/08/stable-channel-update-for-desktop.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?32e2f14f"
  );
  # https://vuxml.freebsd.org/freebsd/1110e286-dc08-11ea-beed-e09467587c17.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cdafeae2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/12");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<84.0.4147.125")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
