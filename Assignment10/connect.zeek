@load base/frameworks/notice

module ConnectScan;

export {
    redef enum Notice::Type += { Connect_Scan };

    const threshold: count = 10 &redef;
    const window: interval = 5min &redef;
}

# completed but empty connections per source IP; expires 5 minutes after the first hit
global connected: table[addr] of count &default=0 &create_expire=window;

# previous notices per source IP; never expires
global notices: table[addr] of count &default=0;

event connection_state_remove(c: connection)
    {
    local s = c$conn$conn_state;

    # full handshake (S, h, A in history), closed again without any data
    if ( ! ( ( s == "SF" || s == "RSTO" || s == "RSTR" ) &&
             "ShA" in c$history &&
             c$orig$size == 0 && c$resp$size == 0 ) )
        return;

    local scanner = c$id$orig_h;
    ++connected[scanner];

    if ( connected[scanner] >= threshold )
        {
        NOTICE([$note=Connect_Scan,
                $src=scanner,
                $msg=fmt("Possible Nmap connect scan (-sT) from %s: %d completed empty connections. Previous notices for this scan: %d",
                         scanner, threshold, notices[scanner])]);

        ++notices[scanner];
        delete connected[scanner];    # counter and window start over
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

    print fmt("Total connect scan notices: %d", total);
    }
