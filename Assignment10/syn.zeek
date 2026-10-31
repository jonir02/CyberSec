@load base/frameworks/notice

module SynScan;

export {
    redef enum Notice::Type += { SYN_Scan };

    const threshold: count = 10 &redef;
    const window: interval = 5min &redef;
}

# half-open connections per source IP; expires 5 minutes after the first hit
global half_open: table[addr] of count &default=0 &create_expire=window;

# previous notices per source IP; never expires
global notices: table[addr] of count &default=0;

event connection_state_remove(c: connection)
    {
    local s = c$conn$conn_state;

    # SYN without answer (S0), SYN rejected (REJ),
    # or SYN / SYN-ACK / RST without final ACK (RSTO, RSTOS0)
    if ( ! ( s == "S0" || s == "REJ" || s == "RSTOS0" ||
             ( s == "RSTO" && "A" !in c$history ) ) )
        return;

    local scanner = c$id$orig_h;
    ++half_open[scanner];

    if ( half_open[scanner] >= threshold )
        {
        NOTICE([$note=SYN_Scan,
                $src=scanner,
                $msg=fmt("Possible Nmap SYN scan (-sS) from %s: %d half-open connections. Previous notices for this scan: %d",
                         scanner, threshold, notices[scanner])]);

        ++notices[scanner];
        delete half_open[scanner];    # counter and window start over
        }
    }

event zeek_done()
    {
    local total = 0;

    for ( scanner, n in notices )
        {
        print fmt("%s: %d notices", scanner, n);
        total += n;
        }

    print fmt("Total SYN scan notices: %d", total);
    }


