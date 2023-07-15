#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2021 Jacques Vidrine and contributors
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

include('compat.inc');

if (description)
{
  script_id(146578);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2021-21149",
    "CVE-2021-21150",
    "CVE-2021-21151",
    "CVE-2021-21152",
    "CVE-2021-21153",
    "CVE-2021-21154",
    "CVE-2021-21155",
    "CVE-2021-21156",
    "CVE-2021-21157"
  );

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (48514901-711d-11eb-9846-e09467587c17)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Chrome Releases reports :

This release contains 10 security fixes, including :

- [1138143] High CVE-2021-21149: Stack overflow in Data Transfer.
Reported by Ryoya Tsukasaki on 2020-10-14

- [1172192] High CVE-2021-21150: Use after free in Downloads. Reported
by Woojin Oh(@pwn_exploit) of STEALIEN on 2021-01-29

- [1165624] High CVE-2021-21151: Use after free in Payments. Reported
by Khalil Zhani on 2021-01-12

- [1166504] High CVE-2021-21152: Heap buffer overflow in Media.
Reported by Anonymous on 2021-01-14

- [1155974] High CVE-2021-21153: Stack overflow in GPU Process.
Reported by Jan Ruge of ERNW GmbH on 2020-12-06

- [1173269] High CVE-2021-21154: Heap buffer overflow in Tab Strip.
Reported by Abdulrahman Alqabandi, Microsoft Browser Vulnerability
Research on 2021-02-01

- [1175500] High CVE-2021-21155: Heap buffer overflow in Tab Strip.
Reported by Khalil Zhani on 2021-02-07

- [1177341] High CVE-2021-21156: Heap buffer overflow in V8. Reported
by Sergei Glazunov of Google Project Zero on 2021-02-11

- [1170657] Medium CVE-2021-21157: Use after free in Web Sockets.
Reported by Anonymous on 2021-01-26");
  # https://chromereleases.googleblog.com/2021/02/stable-channel-update-for-desktop_16.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e2680b3b");
  # https://vuxml.freebsd.org/freebsd/48514901-711d-11eb-9846-e09467587c17.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9624ed6a");
  script_set_attribute(attribute:"solution", value:
"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21157");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-21155");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (pkg_test(save_report:TRUE, pkg:"chromium<88.0.4324.182")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
