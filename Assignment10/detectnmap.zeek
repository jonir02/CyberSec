@load base/frameworks/notice

module Nmap;

export {
    const threshold: count = 20 &redef;

    global hits: table[string, addr] of count &default=0;
    global notices: table[string, addr] of count &default=0;
}

#################################################
# SYN SCAN (-sS)
#################################################

module Nmap::SynScan;

export {
    redef enum Notice::Type += { Detected };
}

event connection_state_remove(c: connection)
    {
    local s = c$conn$conn_state;

    if ( s == "S0" || s == "REJ" || s == "RSTOS0" ||
         ( s == "RSTO" && "A" !in c$history ) )
        {
        local ip = c$id$orig_h;

        ++Nmap::hits["SYN", ip];

        if ( Nmap::hits["SYN", ip] >= Nmap::threshold )
            {
            ++Nmap::notices["SYN", ip];
            Nmap::hits["SYN", ip] = 0;
            }
        }
    }

#################################################
# CONNECT SCAN (-sT)
#################################################

module Nmap::ConnectScan;

export {
    redef enum Notice::Type += { Detected };
}

event connection_state_remove(c: connection)
    {
    local s = c$conn$conn_state;

    if ( ( s == "SF" || s == "RSTO" || s == "RSTR" ) &&
         "ShA" in c$history &&
         c$orig$size == 0 && c$resp$size == 0 )
        {
        local ip = c$id$orig_h;

        ++Nmap::hits["CONNECT", ip];

        if ( Nmap::hits["CONNECT", ip] >= Nmap::threshold )
            {
            ++Nmap::notices["CONNECT", ip];
            Nmap::hits["CONNECT", ip] = 0;
            }
        }
    }

#################################################
# FINAL NOTICES
#################################################

event zeek_done()
    {
    for ( [scan, ip] in Nmap::notices )
        {
        if ( scan == "SYN" )
            NOTICE([$note=Nmap::SynScan::Detected,
                    $src=ip,
                    $msg=fmt("Nmap SYN scan (-sS) from %s. Total Notices: %d",
                             ip, Nmap::notices[scan, ip])]);

        else if ( scan == "CONNECT" )
            NOTICE([$note=Nmap::ConnectScan::Detected,
                    $src=ip,
                    $msg=fmt("Nmap Connect scan (-sT) from %s. Total Notices: %d",
                             ip, Nmap::notices[scan, ip])]);
        }
    }

