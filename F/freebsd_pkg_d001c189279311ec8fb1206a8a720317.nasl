#%NASL_MIN_LEVEL 70300
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

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153983);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2021-42013");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"FreeBSD : Apache httpd -- Path Traversal and Remote Code Execution (d001c189-2793-11ec-8fb1-206a8a720317)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The Apache http server project reports :

critical: Path Traversal and Remote Code Execution in Apache HTTP
Server 2.4.49 and 2.4.50 (incomplete fix of CVE-2021-41773)
(CVE-2021-42013).

It was found that the fix for CVE-2021-41773 in Apache HTTP Server
2.4.50 was insufficient. An attacker could use a path traversal attack
to map URLs to files outside the directories configured by Alias-like
directives.

If files outside of these directories are not protected by the usual
default configuration 'require all denied', these requests can
succeed. If CGI scripts are also enabled for these aliased pathes,
this could allow for remote code execution.

This issue only affects Apache 2.4.49 and Apache 2.4.50 and not
earlier versions.

Acknowledgements: Reported by Juan Escobar from Dreamlab Technologies,
Fernando Munoz from NULL Life CTF Team, and Shungo Kumasaka");
  # https://vuxml.freebsd.org/freebsd/d001c189-2793-11ec-8fb1-206a8a720317.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c28c816");
  script_set_attribute(attribute:"solution", value:
"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42013");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache 2.4.50 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache 2.4.49/2.4.50 Traversal RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache24");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (pkg_test(save_report:TRUE, pkg:"apache24>=2.4.49<2.4.51")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
