# security.tcl for netbots.tcl v3.35 & up
# designed to work with eggdrop 1.3.28 or higher
# Johoho's Eggdrop Page - http://johoho.eggheads.org/eggdrop/
# security.tcl copyright (c) 2000-2001 by johoho <johoho@hojo-net.de>
# code related with paranoid_rebinds is (c) 2001 by Abraham <abraham@mud.pl>
# netbots.tcl copyright (c) 1998-2001 by slennox <slennox@egghelp.org>

## security.tcl component script v0.52.0, 09.02.2002##

# History:
# 
# v0.10.0, 16.06.2000 - initial design and concept
# v0.11.0, 18.06.2000 - fixed a small bug
# v0.12.0, 19.06.2000 - added booting support
# v0.20.0, 07.01.2001
# till
# v0.49.0, 14.06.2001 - not public, internal devel. versions, in which existing
#                       code was cleaned-up and optimisation was done, detalis:
#                     * added warning message in case when eggdrop is older than
#                       1.6.4 because of broken booting code in "pre-1.6.4" eggs
#                       (Abraham)
#                     * added suport for .deluser command was added (Abraham)
# v0.50.0, 28.06.2001 - 1st public release after freatures addition tested ealier
#                       in dev-versions, implemented by Abraham, details follows:
#                     * added posibility to rebind critcial commads to
#                       higher flags,
#                     * added logging (by notes) for selected commands,
#                       note is send to people specified in se_spy_note
#                       variable,
#                     * added secured .whois command,
#                     * added secured .match command, 
#                     * added slighty reworked .chhandle command,
#                     * added secured +-host routines because of security
#                       flaw in eggdrop (fixed in eggdrop 1.6.5),
#                     * added optix's safe .die command writen at Ben Dover
#                       request and added DCCcomplex
# v0.50.1, 29.06.2001 - improved DCCcomplex
# v0.51.0, 06.07.2001 - recoded seriously command handling ! From now script
#                       is capable to secure commands rebinded to 3-rd party
#                       scripts, which i.e. extends funcionality of specific
#                       commands. Cmds: whois, match & chhandle are excluded
#                       from that change.
# v0.51.1, 11.07.2001 - fixed minor/annynoing bug in DCCcomplex and improved
#                       it a bit.
# v0.51.2, 12.06.2001 - improved/recoded: safe die, it uses now bind FILT.
# v0.51.3, 16.06.2001 - improved: safe whois.
# v0.51.4, 28.08.2001 - fixed: case-sensivity bug.
# v0.52.0, 09.02.2002 - added: "Added" XTRA field to usefile records. Will be
#                       recorded info about who added record and when, also
#                       added: "ChangedFlag", "ChangedBotFlag" - and last but
#                       least "ChangedBotAddr" fields to userfile records.
#                       Will be recored previous state of flags, botflags and
#                       botaddress and of course who/when changed it,
#                       added: checks of NOTES MODULE presence, additional
#                       rebinds due changes appiled by poptix on egg 1.6.7
#                       and safe who &
# v0.52.0, 09.02.2002 * reverted: change in safe die, it's uses again ordinar
#                       bind instead FILT.
# v0.52.0, 08.11.2002 * improved/recoded: secured +-host, it uses from now 
#                       bind FILT.
# v0.52.0, 09.02.2002 * fixed: some minor bugs in dcc:se_common procedure.

# Todo:
# "dynamic" +f flag handling.

# thanks slennox for netbots.tcl

proc mod:check {what} {
  foreach m [modules] {
    if {[string match "*$what*" [lindex $m 0]]} {return 1} else {continue}
  }
  return 0
}

if {$se_spy_note != ""} {
  if {[mod:check notes]} { 
    putlog "SECURITY: notes support is active.."
  } else {
    putlog "SECURITY: You need the notes module to use notes support in this script"
    set se_spy_note ""
  }
}

if {$se_DCCcomplex != 0} {
putlog "SECURITY:DCCcomplex by \002AbrahaM\002 is activated"
putlog "SECURITY/DCCcomplex: idle-checking interval is $se_DCCcomplexinterval mins"
putlog "SECURITY/DCCcomplex: Warn: $se_DCCcomplexwarntime mins Away: $se_DCCcomplexawaytime mins Boot: $se_DCCcomplexkicktime mins"
}

if {![info exists {se_joinctrl_botnet_master_check}]} { set se_joinctrl_botnet_master_check 0 }
if {![info exists {se_joinctrl_perm_owner_check}]} { set se_joinctrl_perm_owner_check 0 }
if {($se_joinctrl_perm_owner_check == 1) && ($se_joinctrl_botnet_master_check == 1)} { set se_joinctrl_botnet_master_check 0 }

if {$se_paranoid_dcc_rebinds == 0 && $se_spy_mode == 1} {
  set se_spy_mode 0
  putlog "SECURITY component WARNING: Spymode is NOT activated, to activate it, turn on security extensions/rebinds" 
}

if {[string trimleft [lindex [split $version] 1] 0] < 1060400} {
  putlog "SECURITY component WARNING: booting support for -user/deluser command may not work properly with eggdrop versions older that 1.6.4"
}

if {![info exists userinfover]} {
  if {![info exists whois-fields]} {
    set whois-fields ""
  }
}

set security-fields "Added ChangedFlag ChangedBotFlag ChangedBotAddr"
foreach field [string tolower ${security-fields}] {
  if {[lsearch -exact [string tolower ${whois-fields}] $field] == -1} {append whois-fields " " [string toupper $field]}
}

proc ispermown { handle } {
  global owner
  if {![info exists owner] || $owner == ""} {return 0}
  if {$handle == "%"} {return 0}
  foreach zowner [split [string trim $owner " "] ,] {
    if {[string tolower $handle] == [string tolower $zowner]} { set isowner 1 } }
    if {[info exists isowner]} {
    if {[matchattr $handle n]} {return 1} {return 0}
  }
  return 0
}

proc dcc:se_common {idx text} {
  set ok 0
  set hand [idx2hand $idx]
  set cmd [string tolower [lindex $text 0]]
  switch -glob -- $cmd {
    ".-cha*"  { set sec 1 ; set log 1 ; set ext 0 }
    ".+cha*"  { set sec 1 ; set log 1 ; set ext 0 }
    ".-bo*"   { set sec 1 ; set log 1 ; set ext 0 }
    ".+bo*"   { set sec 1 ; set log 1 ; set ext 1 }
    ".chad*"  { set sec 1 ; set log 1 ; set ext 1 }
    ".bota*"  { set sec 1 ; set log 1 ; set ext 1 }

    ".resta*" { set sec 1 ; set log 0 ; set ext 0 }
    ".bi*"    { set sec 1 ; set log 0 ; set ext 0 }
    ".loa*"   { set sec 1 ; set log 0 ; set ext 0 }
    ".unloa*" { set sec 1 ; set log 0 ; set ext 0 }
    ".deb*"   { set sec 1 ; set log 0 ; set ext 0 }
    ".modul*" { set sec 1 ; set log 0 ; set ext 0 }

    ".+u*"    { set sec 0 ; set log 1 ; set ext 1 }
    ".addu*"  { set sec 0 ; set log 1 ; set ext 1 }
    ".chatt*" { set sec 0 ; set log 1 ; set ext 1 }
  }
  if {$sec} {
    if {![ispermown $hand]} {
      putidx $idx "You do not have access to issue $cmd command."
      return
    } else {
      set ok 1
    }
  } elseif {$sec == 0} {
    set ok 1
  }
  if {$log} {
    se_command_log $ok $hand $text
  }
  if {$ext == 1 && $ok == 1} {
    set target [string tolower [lindex $text 1]]
    set option [string tolower [lindex $text 2]]
    set add 0 ; set chn 0
    switch -glob -- $cmd {
      ".chad*"  { set chn 1 }
      ".bota*"  { set chn 1 }
      ".chatt*" { set chn 1 }
      ".+u*"    { set add 1 }
      ".+bo*"   { set add 1 }
      ".addu*"  { set add 1 }
    }
    if {$chn} {
      if {![validuser $target]} {
        putidx $idx "Can't find entry mathing $target"
        return
      }
      switch -glob -- $cmd {
        ".chad*"  { set prv_stt [getuser $target botaddr] }
        ".bota*"  { set prv_stt [getuser $target botfl] }
        ".chatt*" { set prv_stt [chattr $target -|-] }
      }
      if {$prv_stt == "-" || $prv_stt == ""} {
        set prv_stt "nothing"
      }
      if {$option == ""} {
        set $option "nothing"
      }
      if {[string match ".chad*" $cmd]} {
        setuser $target XTRA ChangedBotAddr "from $prv_stt by $hand at [strftime "%Y-%m-%d %H:%M"]"
      } elseif {[string match ".bota*" $cmd]} {
        setuser $target XTRA ChangedBotFlag "from $prv_stt by $hand at [strftime "%Y-%m-%d %H:%M"]"
      } elseif {[string match ".chatt*" $cmd]} {
        setuser $target XTRA ChangedFlag "from $prv_stt by $hand at [strftime "%Y-%m-%d %H:%M"]"
      }
    }
    if {$add} {
      if {[string match ".+u*" $cmd]} {
        *dcc:+user $hand $idx "$target $option"
      } elseif {[string match ".+bo*" $cmd]} {
        *dcc:+bot $hand $idx "$target $option"
      } elseif {[string match ".addu*" $cmd]} {
        *dcc:adduser $hand $idx $target
        if {[string match "!*" $target]} {
          regsub -- "!" $target "" target
        }
      }
      setuser $target XTRA Added "by $hand as $target at [strftime "%Y-%m-%d %H:%M"]"
      set ok 0
    }
  }
  if {$ok} {
    return $text
  }
}

proc se_command_log {ok hand text} {
global se_spy_note se_spy_mode se_spy_victims
  if {($se_spy_victims == "all") || ($se_spy_victims != "all" && [matchattr $hand $se_spy_victims])} {
    foreach recipient $se_spy_note {
      if {[validuser $recipient] && ([string tolower $recipient] != [string tolower $hand])} {
        if {$ok} {
          sendnote SECURITY $recipient [join "$hand issued command: $text"]
        } else {
          sendnote SECURITY $recipient [join "$hand tried to issue command: $text"]
        }
      }
    }
  }
}

# se_whois 1.12
proc dcc:se_whois {hand idx arg} {
  set arg  [string tolower $arg]
  set hand [string tolower $hand]
  if {$arg == ""} {
    putidx $idx "Usage: whois <handle>"
    return 0
  } elseif {[string length $arg] > 160} {
    return 0
  } elseif {![validuser $arg]} {
    putidx $idx "Can't find anyone matching that."
    return 0
  } elseif {[matchattr $hand -n] && [matchattr $arg b]} {
    putidx $idx "You can't view information about bots!"
    return 0
  } elseif {$hand != $arg && ([matchattr $hand -p] && [matchattr $arg p])} {
    putidx $idx "You can't view information about users with higher flags than yours!"
    return 0
  } elseif {([matchattr $hand -o] && [matchattr $arg o]) || ([matchattr $hand -v] && [matchattr $arg v])} {
    putidx $idx "You can't view information about users with higher flags than yours!"
    return 0
  } elseif {[matchattr $hand -m] && [matchattr $arg m]} {
    putidx $idx "You can't view information about users with higher flags than yours!"
    return 0
  }
  foreach chan [channels] {
    if {($hand != $arg && [matchattr $hand -m]) && (([matchattr $hand |-o $chan] && [matchattr $arg |o $chan]) || ([matchattr $hand |-v $chan] && [matchattr $arg |v $chan]))} {
      putidx $idx "You can't view information about users with higher channel flags than yours!"
      return 0
    } elseif {($hand != $arg && [matchattr $hand -m] && [matchattr $hand |-m $chan]) && [matchattr $arg |m $chan]} {
      putidx $idx "You can't view information about users with higher channel flags than yours!"
      return 0
    } elseif {($hand != $arg && [matchattr $hand -m] && [matchattr $hand |m $chan]) && (([matchattr $arg v] || [matchattr $arg o] || [matchattr $arg f]) && !([matchattr $arg |v $chan] || [matchattr $arg |o $chan] || [matchattr $arg |f $chan]))} {
      putidx $idx "You can't view information about users with global flags!"
      return 0
    }
  }
  *dcc:whois $hand $idx $arg
}

# se_match 1.0
proc dcc:se_match {hand idx arg} {
  set n_h [lindex $arg 0]
  if {$arg == ""} {
    putidx $idx "Usage: match <attr> \[channel \[\[start\] limit\]"
    putidx $idx "or:    match <wildcard-string> \[\[start\] limit\]"
    return 0
  } elseif {![validuser $n_h] && [matchattr $hand -m]} {
    putidx $idx "You can't use wildcard or flag matching"
    return 0
  } elseif {[matchattr $hand -m] && ([matchattr $arg b] || [matchattr $arg m] || [matchattr $arg n])} {
    putidx $idx "You can't view information about bots or users with higher flags than yours!"
    return 0
  } else {
    *dcc:match $hand $idx $arg
  }
}

# se_chhandle 1.0
proc dcc:se_chhandle {hand idx arg} {
  set old_h [lindex [split [string tolower $arg]] 0]
  set new_h [lindex [split $arg] 1]
  set hand [string tolower $hand]
  if {$old_h == ""} {
    putidx $idx "Usage: chhandle <oldhandle> <newhandle>"
    return 0
  } elseif {![validuser $old_h]} {
    putidx $idx " Can't find anyone matching that."
    return 0
  } elseif {$new_h == ""} {
    putidx $idx "You forget to enter newhandle!"
    return 0
  } elseif {([matchattr $hand +m-n] && $hand != $old_h) && [matchattr $old_h m]} {
    putidx $idx "You can't change other master handle!"
    return 0
  } elseif {![ispermown $hand] && (([matchattr $hand n] && $hand != $old_h) && [matchattr $old_h n])} {
    putidx $idx "You can't change other owner handle!"
    return 0
  } else {
    *dcc:chhandle $hand $idx $arg
  }
}

# DCCcomplex v1.02
# DCCcomplex is inspired by Chair's <chair@gws.org> DCC-AUTOAWAY.TCL
proc se_DCCcomplex {} {
global botnet-nick se_DCCcomplex se_DCCcomplexwarntime se_DCCcomplexawaytime se_DCCcomplexkicktime se_DCCcomplexawaymsgawa se_DCCcomplexinterval
  if {$se_DCCcomplex == 0} {
    return 1
  }
  foreach dccinfo [dcclist] {
    if {[lindex $dccinfo 3] == "CHAT"} {
      set se_DCCcomplex_idx "[lindex $dccinfo 0]"
      set se_DCCcomplex_han "[lindex $dccinfo 1]"
      if {[getdccidle $se_DCCcomplex_idx] == ""} {
        continue
      }
      set se_DCCcomplex_idle "[expr [getdccidle $se_DCCcomplex_idx] * 1.000 / 60 ]"
      if {($se_DCCcomplexkicktime > 0) && ($se_DCCcomplex_idle >= $se_DCCcomplexkicktime)} {
        putlog "SECURITY/DCCcomplex: autobooting [lindex $dccinfo 1] because of his/her idle, which was greater than $se_DCCcomplexkicktime minutes"
        killdcc $se_DCCcomplex_idx
        setuser $se_DCCcomplex_han XTRA DCCcomplexon${botnet-nick}warned
      } elseif {($se_DCCcomplexawaytime > 0) && ($se_DCCcomplex_idle >= $se_DCCcomplexawaytime) && ([getdccaway $se_DCCcomplex_idx] == "")} {
        setdccaway $se_DCCcomplex_idx "SECURITY/DCCcomplex: $se_DCCcomplexawaymsgawa"
        putlog "SECURITY/DCCcomplex: autoawaying [lindex $dccinfo 1] because of his/her idle, which was greater than $se_DCCcomplexawaytime minutes"
      } elseif {($se_DCCcomplexwarntime > 0) && ($se_DCCcomplex_idle >= $se_DCCcomplexwarntime) && ([getdccaway $se_DCCcomplex_idx] == "")} {
        if {[getuser $se_DCCcomplex_han XTRA DCCcomplexon${botnet-nick}warned] == ""} {
          setuser $se_DCCcomplex_han XTRA DCCcomplexon${botnet-nick}warned 0
        }
        if {[getuser $se_DCCcomplex_han XTRA DCCcomplexon${botnet-nick}warned] == "0"} {
          putlog "SECURITY/DCCcomplex: autowarning [lindex $dccinfo 1] because of his/her idle, which was greater than $se_DCCcomplexwarntime minutes"
          setuser $se_DCCcomplex_han XTRA DCCcomplexon${botnet-nick}warned 1
        }
      }
    }
  }
  timer $se_DCCcomplexinterval se_DCCcomplex
}

foreach timer [timers] {
  if {"[lindex $timer 1]" == "se_DCCcomplex"} {
    killtimer [lindex $timer 2]
  }
}

timer $se_DCCcomplexinterval se_DCCcomplex

if {$se_DCCcomplex == 1} {
  bind AWAY - "*" se_DCCcomplex_kill_warned_away
  bind chpt - * se_DCCcomplex_kill_warned_chpt
}

proc se_DCCcomplex_kill_warned_chpt {bot hand idx chan} {
global botnet-nick
  if {[string tolower $bot] == [string tolower ${botnet-nick}]} {
    setuser $hand XTRA DCCcomplexon${botnet-nick}warned
  }
}

proc se_DCCcomplex_kill_warned_away {bot idx txt} {
global botnet-nick
  if {([string tolower $bot] == [string tolower ${botnet-nick}]) && ($txt == "")} {
    set hand [idx2hand $idx]
    setuser $hand XTRA DCCcomplexon${botnet-nick}warned
  }
}

# +-host 1.0
proc dcc:se_hostp {idx arg} {se_host $idx $arg *dcc:+host}
proc dcc:se_hostm {idx arg} {se_host $idx $arg *dcc:-host}
proc se_host {idx arg h_what} {
global version
  set whom [lindex [split $arg] 1]
  set host [lindex [split $arg] 2]
  set hand [idx2hand $idx]
  if {$host == ""} {
    putidx $idx "You didn't specified hostmask"
    return
  }
  foreach chan [channels] {
    if {[string trimleft [lindex [split $version] 1] 0] < 1060500} {
      if {([matchattr $hand -m] && [matchattr $hand |m $chan]) && [matchattr $whom b]} {
        putidx $idx "You don't have access to bot hostmasks"
        return
      }
    }
  }
  return $arg
}

# who 1.1
proc dcc:se_who {hand idx arg} {
  if {([matchattr $hand -m] || [matchattr $hand -t]) && [matchattr $arg b]} {
    putcmdlog "#$hand# who $arg"
    putidx $idx "You don't have access to bot data"
    return 0
  } elseif {$arg != ""} {
    putcmdlog "#$hand# who $arg"
    if {![validuser $arg]} {
      putidx $idx "Hey, I don't have entry called $arg in userfile"     
      return 0
    } elseif {[validuser $arg] && ![matchattr $arg b]} {
      putidx $idx "Hey, that is user - not bot !"
      return 0
    }
  }
  if {([matchattr $hand -m] || [matchattr $hand -t])} {
    putcmdlog "#$hand# who $arg"
    putidx $idx "Party line members:  (* = owner, + = master, @ = op)"
    putidx $idx "Idx  Nick       Host                                 Console"
    putidx $idx "---- ---------- ------------------------------------ ------------"
    foreach person [dcclist chat] {
      set w_idx  [lindex $person 0]
      set w_whom [lindex $person 1]
      set w_host [lindex $person 2]
      set w_console [lindex [console $w_idx] 1]
      if {[matchattr $hand n]} {
        set w_prefix "*"
      } elseif {[matchattr $hand +m-n]} {
        set w_prefix "+"
      } elseif {[matchattr $hand +o-mn]} {
        set w_prefix "@"
      } else {
        set w_prefix " "
      }
      putidx $idx [format "%-1s %-10s %-36s %-1s" \[$w_idx\] $w_prefix$w_whom $w_host $w_console]
    }
  } else {
  *dcc:who $hand $idx $arg
  }
}

# -user 1.0
proc dcc:se_-user   {hand idx arg} {se_duser $hand $idx $arg -user}
proc dcc:se_deluser {hand idx arg} {se_duser $hand $idx $arg deluser}
proc se_duser {hand idx arg d_what} {
global nb_flag owner se_abrahams_paranoid_rebinds se_spy_mode se_spy_note
  if {$arg == ""} {
    putdcc $idx "Usage: $d_what <hand>"
    return 0
  } elseif {![validuser $arg]} {
    putdcc $idx "No such user!"
    return 0
  } elseif {[matchattr $arg b]} {
    putdcc $idx "You can't delete a bot!"
      if {[ispermown $hand]} {
        putdcc $idx "Use instead -bot"
      }
    return 0
  } elseif {[string tolower $hand] == [string tolower $arg]} {
    putdcc $idx "You can't delete yourself, ask somebody for it <g>!"
    return 0
  } elseif {[ispermown $arg]} {
    putdcc $idx "You can't delete an permanent owner!"
    return 0
  } elseif {![ispermown $hand] && ([matchattr $hand n] && [matchattr $arg n])} {
    putdcc $idx "You can't delete an other owner!"
    return 0
  } elseif {[matchattr $hand +m-n] && [matchattr $arg m]} {
    putdcc $idx "You can't delete an other master!"
    return 0
  } else {
    deluser $arg
    putlog "Deleted $arg."
    if {$se_abrahams_paranoid_rebinds == 1  && $se_spy_mode == 1} {
    se_command_log 1 $hand ".$d_what $arg"
    }
    set i 0
    set j ""
    foreach tmp [dcclist] {
      if {[string tolower $arg] == [string tolower [lindex $tmp 1]]} {
        killdcc [lindex $tmp 0]
        incr i
      }
    }
    foreach tmp [whom *] {
      set awho "[lindex [split $tmp] 0]"
      set abot "[lindex [split $tmp] 1]"
      if {($awho == $arg) && ([matchattr $abot $nb_flag])} {
        boot $awho@$abot "You lost access to that botnet"
        lappend j "$awho@$abot"
      }
    }
    if {$i != "0"} {
      putlog "Killed $i connection(s) by $arg."
    }
    if {$j != ""} {
      putlog "Booted $j from partyline"
    }
    return 1
  }
}

proc se_joinctrl {hand idx} {
  global se_joinctrl_botnet_master_check se_joinctrl_perm_owner_check owner
  if {($se_joinctrl_botnet_master_check == 1)} {
    if {![matchattr $hand t]} {
      putdcc $idx "Sorry, only botnet_masters (+t) may use that bot"
      boot $hand "access denied"
      putlog "Denied partyline access to $hand (non botnet-master)."
      return 1
    }
  }
  if {($se_joinctrl_perm_owner_check == 1)} {
    if {![ispermown $hand]} {
      putdcc $idx "Sorry, only PERMANENT owners may use that bot"
      boot $hand "access denied"
      putlog "Denied partyline access to $hand (non-perm owner)."
      return 1
    }
  }
}

proc dcc:se_die {hand idx text} {
global diereason uptime botnet-nick
set diereason [lindex $text 1]
set up [unixtime]
incr up -$uptime
putdcc $idx "Are you absolutely sure that you want me to DIE ?"
putdcc $idx "I am ${botnet-nick}, and I've been up for [duration $up]!"
putdcc $idx "Type 'yes' if you're sure, anything else to cancel."
control $idx die_control
}

proc die_control {idx arg} {
global diereason
  if {![string compare yes [string tolower [lindex [split $arg] 0]]]} {
    putdcc $idx "*sniffle* okay =("
    putlog "#[idx2hand $idx]# die ($diereason)"
    die "$diereason"
  } else {
    putdcc $idx "Phew !"
  }
  return 1
}

if {$se_joinctrl} {
  bind chon - * se_joinctrl
}

proc se_intelli_unbind {bind2rem} {
  foreach bind [binds $bind2rem] {catch {unbind [lrange $bind 0 2] [lindex $bind 4]}}
}

proc se_intelli_unbind_list {binds2rem_list} {
  foreach bind ${binds2rem_list} {se_intelli_unbind $bind}
}

if {$se_paranoid_msg_unbinds} {
  unbind msg n|- die    *msg:die
  unbind msg m|- save   *msg:save
  unbind msg m|- reset  *msg:reset
  unbind msg m|- rehash *msg:rehash
  unbind msg m|- memory *msg:memory
  unbind msg m|- jump   *msg:jump
  unbind msg m|m status *msg:status
  unbind msg -|- help   *msg:help
  unbind msg -|- whois  *msg:whois
  unbind msg -|- who    *msg:who
}

set se_std_unbind_lst {
  "die"
  "-user"
  "deluser"
  "bots"
  "botinfo"
  "bottree"
  "vbottree"
  "who"
}
se_intelli_unbind_list se_std_unbind_lst

bind dcc n|- die       dcc:se_die
bind dcc m|- -user     dcc:se_-user
bind dcc m|- deluser   dcc:se_-user
bind dcc t|- bots     *dcc:bots
bind dcc t|- botinfo  *dcc:botinfo
bind dcc t|- bottree  *dcc:bottree
bind dcc t|- vbottree *dcc:vbottree
bind filt - ".+h*"     dcc:se_hostp
bind filt - ".-h*"     dcc:se_hostm
bind dcc -   who       dcc:se_who

if {$se_paranoid_dcc_rebinds} {
  set se_paranoid_unbind_lst {
    "whois"
    "match"
    "chhandle"
  }
  se_intelli_unbind_list se_paranoid_unbind_lst

  bind dcc -   match     dcc:se_match
  bind dcc -   whois     dcc:se_whois
  bind dcc -   chhandle  dcc:se_chhandle

  bind filt - ".chatt*"  dcc:se_common
  bind filt - ".addu*"   dcc:se_common
  bind filt - ".+u*"     dcc:se_common

  bind filt - ".-bo*"    dcc:se_common
  bind filt - ".+bo*"    dcc:se_common
  bind filt - ".-cha*"   dcc:se_common
  bind filt - ".+cha*"   dcc:se_common
  bind filt - ".resta*"  dcc:se_common
  bind filt - ".deb*"    dcc:se_common
  bind filt - ".bi*"     dcc:se_common

  bind filt - ".module*" dcc:se_common
  bind filt - ".loa*"    dcc:se_common
  bind filt - ".unloa*"  dcc:se_common
  bind filt - ".chad*"   dcc:se_common
  bind filt - ".bota*"   dcc:se_common
}