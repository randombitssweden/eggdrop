# splitdetect.tcl for netbots.tcl v3.35
# designed to work with eggdrop 1.3.28 or higher
# Johoho's Eggdrop Page - http://johoho.tuts.net/eggdrop/
# splitdetect.tcl copyright (c) 1999,2000 by johoho <johoho@hojo-net.de>
# netbots.tcl copyright (c) 1998-2000 by slennox <slennox@egghelp.org>

## splitdetect.tcl component script v2.02.1, 19.05.2000 ##

# History:
# 
# v1.00.1, 26.12.1999 - initial release, not public
# v2.01.0, 14.01.2000 - public release with some fixed
# v2.01.1, 19.03.2000 - changed header and readme :)
# v2.02.0, 06.05.2000 - fixed a minor bug
# v2.02.1, 19.05.2000 - fixed a readme bug - thanks _eCs_

# thanks to G'Quann who coded this one. thanks slennox for netbots.tcl

proc sd_helpidx {hand chan idx} {
  if {![matchattr $hand m $chan]} {return 0}
  putidx $idx "splitdetect.tcl commands"
  if {[matchattr $hand m]} {
    putidx $idx " For masters:"
    putidx $idx "  netsplits"
  }
  putidx $idx " "
  return 1
}

proc sd_help {hand chan idx cmd} {
global sd_criticaltime sd_showall
  if {[matchattr $hand m|m $chan]} {
    switch -exact -- $cmd {
      "netsplits" {
        if {[matchattr $hand m]} {
          putidx $idx "# netsplits"
          if {$sd_showall} {
            putwrap $idx 3 "This command shows all splittet servers. If a splits continues for more then $sd_criticaltime minutes it'll be shown as critical."
            return 1
          } else {
            putwrap $idx 3 "This command shows all critical splittet servers (Servers which are splittet for more then $sd_criticaltime minutes are considered as critical)."
            return 1
          }
        }
      }
    }
  }
  return 0
}

lappend nb_helpidx "sd_helpidx"
set nb_help(netsplits) "sd_help"



proc utimerid {timerproc} {
foreach timer [timers] {
    if {[lindex [lindex $timer 1] 0] == $timerproc} {return [lindex $timer 0]}
    }
return -1
}

if {![string match *sd:checkforcriticalservers* [timers]]} {timer 1 sd:checkforcriticalservers}

proc raw:splitdetect {from keyword rest} {
global sd_ignore
set rest [string tolower $rest]
set rest [split $rest { }]
if {[lindex $rest 0] != "&servers"} {return 0}
set rest [lrange $rest 1 end]
set rest [string range $rest 1 end]
if {[string match "received squit *" $rest]} {
    sd:split [lindex $rest 2]
    }
if {[string match "received server *" $rest]} {
    sd:rejoin [lindex $rest 2]
    }
}

proc sd:split {server} {
global sdservers sd_ignore sd_showall
set server [string tolower $server]
if {[lsearch -exact $sd_ignore $server] > -1} {return 1}
if {$sd_showall} {putlog "Netsplit detected: $server"}
foreach splitserver [array names sdservers] {
    if {[string match $splitserver $server] || [string match $server $splitserver]} {
        putlog "hmmz... I though $server is already splitted... reseting split-time"
        unset sdservers($splitserver)
        }
    }
set sdservers($server) [unixtime]
}

proc sd:rejoin {server} {
global sdservers sd_showall sd_ignore sd_criticaltime
set server [string tolower $server]
if {[lsearch -exact $sd_ignore $server] > -1} {return 1}
set inarray 0
foreach splitserver [array names sdservers] {
    if {[string match $splitserver $server] || [string match $server $splitserver]} {
            set inarray 1
            set splittime [expr [expr [unixtime] - $sdservers($splitserver)] / 60]
            unset sdservers($splitserver)
            }
    }
if {!$inarray} {
    if {$sd_showall} {putlog "Reconnect detected: $server (unknown splittime)"}
    } else {
    if {$sd_showall} {putlog "Reconnect detected: $server (${splittime}min)"}
    if {$splittime > $sd_criticaltime} {sd:criticalreconnect $server $splittime}
    }
}

proc sd:criticalreconnect {server mins} {
putlog "$server reconnected after ${mins}min"
putallbots "critrec"
}

proc sd:criticalsplit {server} {
putlog "Critical split detected: $server"
}

proc dcc:netsplits {hand idx rest} {
global sdservers sd_criticaltime
putdcc $idx "Current Netsplits:"
putdcc $idx "---"
if {[array size sdservers] == 0} {
    putdcc $idx "none ^_^"
    } else {
    foreach server [array names sdservers] {
        set splittime [expr [expr [unixtime] - $sdservers($server)] / 60]
        if {$splittime > $sd_criticaltime} {
            putdcc $idx "${server}(${splittime}min) <=== CRITICAL!"
            } else {
            putdcc $idx "${server}(${splittime}min)"
            }
        }
    }
putdcc $idx "---"
putdcc $idx "[array size sdservers] servers splitted"
return 1
}

proc sd:checkforcriticalservers {} {
global sdservers sd_lost sd_criticaltime
foreach server [array names sdservers] {
    set splittime [expr [expr [unixtime] - $sdservers($server)] / 60]
    if {$splittime == $sd_criticaltime} {sd:criticalsplit $server}
    if {$splittime > $sd_lost} {
        putlog "Seems that $server got lost in the netsplit..."
        unset sdservers($server)
        }
    }
if {![string match *sd:checkforcriticalservers* [timers]]} {timer 1 sd:checkforcriticalservers}
}

proc bot:critrec {bot command rest} {
#putlog "$bot told me that there's a reconnect after a critical split."
}

proc 001:joinservers {from keyword rest} {
  putquick "JOIN &servers"
  return 0
}

proc JOIN:joinservers {from keyword rest} {
  if {$rest == ":&servers"} {return 1} else {return 0}
}




bind dcc m netsplits dcc:netsplits
bind raw - NOTICE raw:splitdetect
bind raw - 001 001:joinservers
bind raw - JOIN JOIN:joinservers
bind bot - critrec bot:critrec
