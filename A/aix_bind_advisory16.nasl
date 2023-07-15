#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102822);
  script_version("3.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id("CVE-2017-3142", "CVE-2017-3143");
  script_bugtraq_id(99337, 99339);

  script_name(english:"AIX bind Advisory : bind_advisory16.asc (IV98826) (IV98827)");
  script_summary(english:"Checks the version of the bind packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of bind installed that is affected
by multiple security bypass vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of bind installed on the remote AIX host is affected by
the following vulnerabilities :

  - A security bypass exists in the way BIND handles TSIG
    authentication for dynamic updates. A remote,
    unauthenticated attacker can exploit this, via a
    specially crafted request packet containing a valid TSIG
    key name, to transfer the target zone. (CVE-2017-3142)

  - A security bypass exists in the way BIND handles TSIG
    authentication for dynamic updates. A remote,
    unauthenticated attacker can exploit this, via a
    specially crafted request packet containing a valid TSIG
    key name, to force an unauthorized dynamic update.
    (CVE-2017-3143)");
  script_set_attribute(attribute:"see_also", value:"https://aix.software.ibm.com/aix/efixes/security/bind_advisory16.asc");
  script_set_attribute(attribute:"solution", value:
"A fix is available and can be downloaded from the IBM AIX website.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"AIX Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2023 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

include("aix.inc");
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
oslevel = get_kb_item("Host/AIX/version");
if (isnull(oslevel)) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
oslevel = oslevel - "AIX-";

oslevelcomplete = chomp(get_kb_item("Host/AIX/oslevelsp"));
if (isnull(oslevelcomplete)) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
oslevelparts = split(oslevelcomplete, sep:'-', keep:0);
if ( max_index(oslevelparts) != 4 ) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
ml = oslevelparts[1];
sp = oslevelparts[2];

if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This AIX package check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

aix_bind_vulns = {
  "5.3": {
    "12": {
      "09": {
        "bos.net.tcp.client": {
          "minfilesetver":"5.3.12.0",
          "maxfilesetver":"5.3.12.10",
          "patch":"(IV98825m9a)"
        }
      }
    }
  },
  "6.1": {
    "09": {
      "07": {
        "bos.net.tcp.client": {
          "minfilesetver":"6.1.9.0",
          "maxfilesetver":"6.1.9.300",
          "patch":"(IV98826m9a)"
        }
      },
      "08": {
        "bos.net.tcp.client": {
          "minfilesetver":"6.1.9.0",
          "maxfilesetver":"6.1.9.300",
          "patch":"(IV98826m9a)"
        }
      },
      "09": {
        "bos.net.tcp.client": {
          "minfilesetver":"6.1.9.0",
          "maxfilesetver":"6.1.9.300",
          "patch":"(IV98826m9a)"
        }
      },
      "10": {
        "bos.net.tcp.client": {
          "minfilesetver":"6.1.9.0",
          "maxfilesetver":"6.1.9.300",
          "patch":"(IV98826m0a)"
        }
      }
    }
  },
  "7.1": {
    "03": {
      "07": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.3.0",
          "maxfilesetver":"7.1.3.49",
          "patch":"(IV98827m3a)"
        }
      },
      "08": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.3.0",
          "maxfilesetver":"7.1.3.49",
          "patch":"(IV98827m3a)"
        }
      },
      "09": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.3.0",
          "maxfilesetver":"7.1.3.49",
          "patch":"(IV98827m3a)"
        }
      }
    },
    "04": {
      "02": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.4.0",
          "maxfilesetver":"7.1.4.32",
          "patch":"(IV98828m4a)"
        }
      },
      "03": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.4.0",
          "maxfilesetver":"7.1.4.32",
          "patch":"(IV98828m4a)"
        }
      },
      "04": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.4.0",
          "maxfilesetver":"7.1.4.32",
          "patch":"(IV98828m4a)"
        }
      },
      "05": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.4.0",
          "maxfilesetver":"7.1.4.32",
          "patch":"(IV98828m5b)"
        }
      }
    }
  },
  "7.2": {
    "00": {
      "02": {
        "bos.net.tcp.client_core": {
          "minfilesetver":"7.2.0.0",
          "maxfilesetver":"7.2.0.4",
          "patch":"(IV98829m0a)"
        }
      },
      "03": {
        "bos.net.tcp.client_core": {
          "minfilesetver":"7.2.0.0",
          "maxfilesetver":"7.2.0.4",
          "patch":"(IV98829m0a)"
        }
      },
      "04": {
        "bos.net.tcp.client_core": {
          "minfilesetver":"7.2.0.0",
          "maxfilesetver":"7.2.0.4",
          "patch":"(IV98829m0a)"
        }
      },
      "05": {
        "bos.net.tcp.client_core": {
          "minfilesetver":"7.2.0.0",
          "maxfilesetver":"7.2.0.4",
          "patch":"(IV98829m0b)"
        }
      }
    },
    "01": {
      "00": {
        "bos.net.tcp.client_core": {
          "minfilesetver":"7.2.1.0",
          "maxfilesetver":"7.2.1.2",
          "patch":"(IV98830m1a)"
        }
      },
      "01": {
        "bos.net.tcp.client_core": {
          "minfilesetver":"7.2.1.0",
          "maxfilesetver":"7.2.1.2",
          "patch":"(IV98830m1a)"
        }
      },
      "02": {
        "bos.net.tcp.client_core": {
          "minfilesetver":"7.2.1.0",
          "maxfilesetver":"7.2.1.2",
          "patch":"(IV98830m1a)"
        }
      },
      "03": {
        "bos.net.tcp.client_core": {
          "minfilesetver":"7.2.1.0",
          "maxfilesetver":"7.2.1.2",
          "patch":"(IV98830m1b)"
        }
      }
    }
  }
};

version_report = "AIX " + oslevel;
if ( empty_or_null(aix_bind_vulns[oslevel]) ) {
  os_options = join( sort( keys(aix_bind_vulns) ), sep:' / ' );
  audit(AUDIT_OS_NOT, os_options, version_report);
}

version_report = version_report + " ML " + ml;
if ( empty_or_null(aix_bind_vulns[oslevel][ml]) ) {
  ml_options = join( sort( keys(aix_bind_vulns[oslevel]) ), sep:' / ' );
  audit(AUDIT_OS_NOT, "ML " + ml_options, version_report);
}

version_report = version_report + " SP " + sp;
if ( empty_or_null(aix_bind_vulns[oslevel][ml][sp]) ) {
  sp_options = join( sort( keys(aix_bind_vulns[oslevel][ml]) ), sep:' / ' );
  audit(AUDIT_OS_NOT, "SP " + sp_options, version_report);
}

foreach package ( keys(aix_bind_vulns[oslevel][ml][sp]) ) {
  package_info = aix_bind_vulns[oslevel][ml][sp][package];
  minfilesetver = package_info["minfilesetver"];
  maxfilesetver = package_info["maxfilesetver"];
  patch =         package_info["patch"];
  if (aix_check_ifix(release:oslevel, ml:ml, sp:sp, patch:patch, package:package, minfilesetver:minfilesetver, maxfilesetver:maxfilesetver) < 0) flag++;
}

if (flag)
{
  aix_report_extra = ereg_replace(string:aix_report_get(), pattern:"[()]", replace:"");
  aix_report_extra = ereg_replace(string:aix_report_extra, pattern:"[|]", replace:" or ");
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : aix_report_extra
  );
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bos.net.tcp.client");
}
