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
  script_id(109228);
  script_version("1.5");
  script_cvs_date("Date: 2019/07/10 16:04:13");

  script_cve_id("CVE-2018-2755", "CVE-2018-2758", "CVE-2018-2759", "CVE-2018-2761", "CVE-2018-2762", "CVE-2018-2766", "CVE-2018-2769", "CVE-2018-2771", "CVE-2018-2773", "CVE-2018-2775", "CVE-2018-2776", "CVE-2018-2777", "CVE-2018-2778", "CVE-2018-2779", "CVE-2018-2780", "CVE-2018-2781", "CVE-2018-2782", "CVE-2018-2784", "CVE-2018-2786", "CVE-2018-2787", "CVE-2018-2805", "CVE-2018-2810", "CVE-2018-2812", "CVE-2018-2813", "CVE-2018-2816", "CVE-2018-2817", "CVE-2018-2818", "CVE-2018-2819", "CVE-2018-2839", "CVE-2018-2846", "CVE-2018-2877");

  script_name(english:"FreeBSD : MySQL -- multiple vulnerabilities (57aec168-453e-11e8-8777-b499baebfeaf)");
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
"Oracle reports :

MySQL Multiple Flaws Let Remote Authenticated Users Access and Modify
Data, Remote and Local Users Deny Service, and Local Users Access Data
and Gain Elevated Privileges

- A local user can exploit a flaw in the Replication component to gain
elevated privileges [CVE-2018-2755].

- A remote authenticated user can exploit a flaw in the GIS Extension
component to cause denial of service conditions [CVE-2018-2805].

- A remote authenticated user can exploit a flaw in the InnoDB
component to cause denial of service conditions [CVE-2018-2782,
CVE-2018-2784, CVE-2018-2819].

- A remote authenticated user can exploit a flaw in the Security
Privileges component to cause denial of service conditions
[CVE-2018-2758, CVE-2018-2818].

- A remote authenticated user can exploit a flaw in the DDL component
to cause denial of service conditions [CVE-2018-2817].

- A remote authenticated user can exploit a flaw in the Optimizer
component to cause denial of service conditions [CVE-2018-2775,
CVE-2018-2778, CVE-2018-2779, CVE-2018-2780, CVE-2018-2781,
CVE-2018-2816].

- A remote user can exploit a flaw in the Client programs component to
cause denial of service conditions [CVE-2018-2761, CVE-2018-2773].

- A remote authenticated user can exploit a flaw in the InnoDB
component to partially modify data and cause denial of service
conditions [CVE-2018-2786, CVE-2018-2787].

- A remote authenticated user can exploit a flaw in the Optimizer
component to partially modify data and cause denial of service
conditions [CVE-2018-2812].

- A local user can exploit a flaw in the Cluster ndbcluster/plugin
component to cause denial of service conditions [CVE-2018-2877].

- A remote authenticated user can exploit a flaw in the InnoDB
component to cause denial of service conditions [CVE-2018-2759,
CVE-2018-2766, CVE-2018-2777, CVE-2018-2810].

- A remote authenticated user can exploit a flaw in the DML component
to cause denial of service conditions [CVE-2018-2839].

- A remote authenticated user can exploit a flaw in the Performance
Schema component to cause denial of service conditions
[CVE-2018-2846].

- A remote authenticated user can exploit a flaw in the Pluggable Auth
component to cause denial of service conditions [CVE-2018-2769].

- A remote authenticated user can exploit a flaw in the Group
Replication GCS component to cause denial of service conditions
[CVE-2018-2776].

- A local user can exploit a flaw in the Connection component to cause
denial of service conditions [CVE-2018-2762].

- A remote authenticated user can exploit a flaw in the Locking
component to cause denial of service conditions [CVE-2018-2771].

- A remote authenticated user can exploit a flaw in the DDL component
to partially access data [CVE-2018-2813]."
  );
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2018-3678067.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?76507bf8"
  );
  # https://vuxml.freebsd.org/freebsd/57aec168-453e-11e8-8777-b499baebfeaf.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2312f6f4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb100-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb101-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb102-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb55-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql55-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql56-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql57-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:percona55-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:percona56-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:percona57-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/23");
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

if (pkg_test(save_report:TRUE, pkg:"mariadb55-server<5.5.60")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb100-server<10.0.35")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb101-server<10.1.33")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb102-server<10.2.15")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mysql55-server<5.5.60")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mysql56-server<5.6.40")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mysql57-server<5.7.22")) flag++;
if (pkg_test(save_report:TRUE, pkg:"percona55-server<5.5.60")) flag++;
if (pkg_test(save_report:TRUE, pkg:"percona56-server<5.6.40")) flag++;
if (pkg_test(save_report:TRUE, pkg:"percona57-server<5.7.22")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
